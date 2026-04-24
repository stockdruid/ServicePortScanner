#pragma once

// 토큰 버킷 rate limiter.
// - 기본 100 tokens/s, 버킷 용량 100.
// - 여러 코루틴이 동시 acquire() 해도 안전: 내부 strand 로 직렬화.
// - 각 acquire() 호출은 자신만의 로컬 timer 를 써서 서로 간섭 없음.

#include <boost/asio/awaitable.hpp>
#include <boost/asio/strand.hpp>
#include <chrono>

namespace sps::net {

class RateLimiter {
public:
    RateLimiter(boost::asio::any_io_executor exec,
                double tokens_per_second = 100.0,
                double bucket_capacity   = 100.0);

    // 토큰 1개를 얻을 때까지 co_await. 스레드 안전.
    boost::asio::awaitable<void> acquire();

    // 런타임 변경 (GUI Settings 에서 호출). 0.1 미만은 무시.
    void set_rate(double tokens_per_second);

    // 테스트용 조회.
    double rate() const noexcept { return rate_; }
    double capacity() const noexcept { return capacity_; }

private:
    void refill_locked();

    boost::asio::strand<boost::asio::any_io_executor> strand_;
    double rate_;
    double capacity_;
    double tokens_;
    std::chrono::steady_clock::time_point last_refill_;
};

} // namespace sps::net
