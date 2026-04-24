#include "rate_limiter.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>

namespace sps::net {

using namespace std::chrono;

RateLimiter::RateLimiter(boost::asio::any_io_executor exec,
                         double tokens_per_second,
                         double bucket_capacity)
    : strand_{boost::asio::make_strand(exec)}
    , rate_{std::max(0.1, tokens_per_second)}
    , capacity_{std::max(1.0, bucket_capacity)}
    , tokens_{capacity_}
    , last_refill_{steady_clock::now()}
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
