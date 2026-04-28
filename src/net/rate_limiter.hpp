#pragma once

// 토큰 버킷 rate limiter — Fixed + Adaptive 모드.
//
// Fixed:    고정 tokens/sec.
// Adaptive: 응답 RTT/loss 기반 자동 조정.
//   - SRTT, RTTVAR : Karn α=1/8, β=1/4 (RFC 6298)
//   - 슬라이딩 윈도우 loss ratio
//   - loss > 5%  → rate × 0.7
//   - loss < 1%  → rate × 1.05 (cap = max_rate)
//   - 조정 주기: 매 100 samples
//
// 참고: zmap (USENIX 2013), masscan throttle, RFC 6298, BBR (ACM Queue 2016).
//
// 여러 코루틴이 동시 acquire() 해도 안전: 내부 strand 로 직렬화.
// on_response 는 lock-free atomic 으로 통계 갱신.

#include <boost/asio/awaitable.hpp>
#include <boost/asio/strand.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace sps::net {

class RateLimiter {
public:
    enum class Mode { Fixed, Adaptive };

    RateLimiter(boost::asio::any_io_executor exec,
                double tokens_per_second = 100.0,
                double bucket_capacity   = 100.0,
                Mode mode = Mode::Fixed,
                double max_rate = 10000.0);

    // 토큰 1개를 얻을 때까지 co_await. 스레드 안전.
    boost::asio::awaitable<void> acquire();

    // 응답 결과 보고. Adaptive 모드에서만 rate 자동 조정.
    // rtt 음수 또는 was_loss=true 이면 loss 로 처리.
    void on_response(std::chrono::milliseconds rtt, bool was_loss);

    // 런타임 변경 (GUI Settings 또는 어댑티브 로직 내부에서). 0.1 미만은 무시.
    void set_rate(double tokens_per_second);

    double rate() const noexcept { return rate_.load(std::memory_order_relaxed); }
    double capacity() const noexcept { return capacity_; }
    Mode mode() const noexcept { return mode_; }

    // 텔레메트리.
    double srtt_ms() const noexcept { return srtt_ms_.load(std::memory_order_relaxed); }
    double loss_ratio() const noexcept;
    std::uint64_t samples() const noexcept { return sample_count_.load(std::memory_order_relaxed); }

private:
    void refill_locked();

    boost::asio::strand<boost::asio::any_io_executor> strand_;
    std::atomic<double> rate_;           // 외부 set_rate / 내부 어댑티브 양쪽에서 수정.
    double capacity_;                     // 생성 후 불변.
    double tokens_;                       // strand 내에서만 접근.
    std::chrono::steady_clock::time_point last_refill_;  // strand 내에서만 접근.

    // 적응형 상태 (lock-free atomic).
    Mode mode_;
    double max_rate_;                     // 생성 후 불변.
    std::atomic<double> srtt_ms_{-1.0};   // -1 = no sample yet
    std::atomic<double> rttvar_ms_{0.0};
    std::atomic<std::uint64_t> sample_count_{0};
    std::atomic<std::uint64_t> loss_count_{0};
};

} // namespace sps::net
