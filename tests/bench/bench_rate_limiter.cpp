// RateLimiter 벤치 — Stage 0 (효율성 개선 연구 자료 §5).
//
// 측정 항목:
//  1. acquire() 오버헤드: strand + atomic + token bucket refill 비용.
//  2. Adaptive 모드 수렴 (높은 loss): rate 가 감속하는지.
//  3. Adaptive 모드 수렴 (clean): rate 가 cap 까지 증속하는지.

#include "net/rate_limiter.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <future>

using namespace std::chrono;
using boost::asio::awaitable;
using boost::asio::use_future;

namespace {

awaitable<void> drain(sps::net::RateLimiter& rl, int n) {
    for (int i = 0; i < n; ++i) co_await rl.acquire();
    co_return;
}

} // namespace

TEST_CASE("RateLimiter::acquire overhead: 1000 acquires, no wait",
          "[bench][rate_limiter]") {
    BENCHMARK("1000 acquires @ 5000 pps (cap >= n, no waiting)") {
        boost::asio::io_context io;
        sps::net::RateLimiter rl{io.get_executor(),
                                  /*rate*/ 5000.0,
                                  /*cap*/ 5000.0};
        auto fut = boost::asio::co_spawn(io, drain(rl, 1000), use_future);
        io.run();
        fut.get();
        return 1000;
    };
}

TEST_CASE("RateLimiter adaptive: converges down on 10% loss",
          "[bench][rate_limiter]") {
    boost::asio::io_context io;
    sps::net::RateLimiter rl{io.get_executor(),
                              /*rate*/ 1000.0,
                              /*cap*/ 1000.0,
                              sps::net::RateLimiter::Mode::Adaptive,
                              /*max_rate*/ 5000.0};

    // 200 samples, 10% loss → 매 100 샘플마다 rate × 0.7.
    for (int i = 0; i < 200; ++i) {
        const bool loss = (i % 10 == 0);
        rl.on_response(milliseconds(loss ? -1 : 50), loss);
    }
    INFO("loss=10%, samples=200, final rate = " << rl.rate());
    REQUIRE(rl.rate() < 1000.0);
}

TEST_CASE("RateLimiter adaptive: converges up on clean network",
          "[bench][rate_limiter]") {
    boost::asio::io_context io;
    sps::net::RateLimiter rl{io.get_executor(),
                              /*rate*/ 1000.0,
                              /*cap*/ 1000.0,
                              sps::net::RateLimiter::Mode::Adaptive,
                              /*max_rate*/ 5000.0};

    for (int i = 0; i < 200; ++i) {
        rl.on_response(milliseconds(20), false);
    }
    INFO("loss=0%, samples=200, final rate = " << rl.rate());
    REQUIRE(rl.rate() > 1000.0);
}

TEST_CASE("RateLimiter adaptive: SRTT/RTTVAR tracking sanity",
          "[bench][rate_limiter]") {
    boost::asio::io_context io;
    sps::net::RateLimiter rl{io.get_executor(), 1000.0, 1000.0,
                              sps::net::RateLimiter::Mode::Adaptive, 5000.0};

    // 100 samples 전부 50ms — SRTT 도 ~50 으로 수렴해야.
    for (int i = 0; i < 100; ++i) {
        rl.on_response(milliseconds(50), false);
    }
    INFO("SRTT after 100 samples (target=50ms) = " << rl.srtt_ms());
    REQUIRE(rl.srtt_ms() > 30.0);
    REQUIRE(rl.srtt_ms() < 70.0);
}
