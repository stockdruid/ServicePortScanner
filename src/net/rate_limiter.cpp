#include "rate_limiter.hpp"

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cmath>

namespace sps::net {

using namespace std::chrono;

namespace {

// 어댑티브 튜닝 상수.
constexpr double kEwmaAlpha = 0.125;        // SRTT  α (RFC 6298)
constexpr double kEwmaBeta  = 0.25;         // RTTVAR β
constexpr double kLossHigh  = 0.05;         // > 5% 면 감속
constexpr double kLossLow   = 0.01;         // < 1% 면 증속
constexpr double kStepDown  = 0.7;
constexpr double kStepUp    = 1.05;
constexpr std::uint64_t kAdjustEvery   = 100;   // samples
constexpr std::uint64_t kWindowReset   = 1000;  // samples

} // namespace

RateLimiter::RateLimiter(boost::asio::any_io_executor exec,
                         double tokens_per_second,
                         double bucket_capacity,
                         Mode mode,
                         double max_rate)
    : strand_{boost::asio::make_strand(exec)}
    , rate_{std::max(0.1, tokens_per_second)}
    , capacity_{std::max(1.0, bucket_capacity)}
    , tokens_{capacity_}
    , last_refill_{steady_clock::now()}
    , mode_{mode}
    , max_rate_{std::max(tokens_per_second, max_rate)}
{}

void RateLimiter::refill_locked() {
    const auto now = steady_clock::now();
    const double dt = duration<double>(now - last_refill_).count();
    const double r = rate_.load(std::memory_order_relaxed);
    tokens_ = std::min(capacity_, tokens_ + dt * r);
    last_refill_ = now;
}

void RateLimiter::set_rate(double tokens_per_second) {
    rate_.store(std::max(0.1, tokens_per_second), std::memory_order_relaxed);
}

double RateLimiter::loss_ratio() const noexcept {
    const auto s = sample_count_.load(std::memory_order_relaxed);
    if (s == 0) return 0.0;
    const auto l = loss_count_.load(std::memory_order_relaxed);
    return static_cast<double>(l) / static_cast<double>(s);
}

void RateLimiter::on_response(std::chrono::milliseconds rtt, bool was_loss) {
    if (mode_ != Mode::Adaptive) return;

    // SRTT/RTTVAR 갱신 (loss 가 아닌 샘플만).
    if (!was_loss && rtt.count() >= 0) {
        const double r = static_cast<double>(rtt.count());
        const double srtt = srtt_ms_.load(std::memory_order_relaxed);
        if (srtt < 0.0) {
            srtt_ms_.store(r, std::memory_order_relaxed);
            rttvar_ms_.store(r * 0.5, std::memory_order_relaxed);
        } else {
            const double new_srtt = (1.0 - kEwmaAlpha) * srtt + kEwmaAlpha * r;
            const double rttvar = rttvar_ms_.load(std::memory_order_relaxed);
            const double new_rttvar =
                (1.0 - kEwmaBeta) * rttvar + kEwmaBeta * std::abs(srtt - r);
            srtt_ms_.store(new_srtt, std::memory_order_relaxed);
            rttvar_ms_.store(new_rttvar, std::memory_order_relaxed);
        }
    }

    const auto samples =
        sample_count_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (was_loss) loss_count_.fetch_add(1, std::memory_order_relaxed);

    // 조정 주기 도달 시에만 rate 변경.
    if (samples % kAdjustEvery != 0) return;

    const auto losses = loss_count_.load(std::memory_order_relaxed);
    const double ratio =
        static_cast<double>(losses) / static_cast<double>(samples);

    const double cur = rate_.load(std::memory_order_relaxed);
    double next = cur;
    if (ratio > kLossHigh) {
        next = std::max(1.0, cur * kStepDown);
    } else if (ratio < kLossLow) {
        next = std::min(max_rate_, cur * kStepUp);
    }
    if (next != cur) {
        rate_.store(next, std::memory_order_relaxed);
    }

    // 슬라이딩 윈도우 리셋 (오래된 통계 제거).
    if (samples >= kWindowReset) {
        sample_count_.store(0, std::memory_order_relaxed);
        loss_count_.store(0, std::memory_order_relaxed);
    }
}

boost::asio::awaitable<void> RateLimiter::acquire() {
    // 1) 상태 변경·timer 사용은 반드시 strand 위에서.
    co_await boost::asio::dispatch(
        boost::asio::bind_executor(strand_, boost::asio::use_awaitable));

    for (;;) {
        refill_locked();
        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            co_return;
        }
        const double need = 1.0 - tokens_;
        const double r    = rate_.load(std::memory_order_relaxed);
        const auto wait = duration_cast<nanoseconds>(
            duration<double>(need / r));

        // 로컬 timer — 동시 acquire 들끼리 서로 취소 못 하게.
        boost::asio::steady_timer t{strand_};
        t.expires_after(wait);
        co_await t.async_wait(boost::asio::use_awaitable);
        // 깨어난 후 루프 돌며 refill → 재시도.
    }
}

} // namespace sps::net
