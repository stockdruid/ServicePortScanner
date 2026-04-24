/*
⠀⠀⠀⠀⢀⠴⣲⣯⣉⣽⣿⡛⠻⣶⠖⢒⢶⣦⣄⠀⠀⠀⠀⠀
⠀⠀⢀⡴⢁⡜⠉⠋⠉⠹⠉⠱⡄⠙⢦⣼⣾⣿⣿⣧⠀⠀⠀⠀
⠀⢀⡞⢀⡞⢀⡄⠀⠀⢀⢸⠀⠹⡀⠈⣟⠿⣿⣿⣟⣉⡇⠀⠀
⣴⣫⠀⢸⢠⣾⡇⢠⠀⢸⢰⢆⠀⡇⠀⢹⣿⣿⣿⣿⣌⡇⠀⠀
⠀⠀⢀⡼⢻⠛⢿⡾⠦⣿⣿⣿⣷⡇⠀⢸⠁⣯⣿⠛⡹⠛⣦⠀
⠀⢰⢨⠀⠈⢓⢺⢁⣀⠀⢿⢀⣼⠃⠀⣸⣠⠃⣇⡴⠁⠀⢸⡇
⠀⠘⣎⢓⢤⣄⣀⣉⡉⣁⣀⣠⣿⡆⢠⠟⠁⠀⠘⠁⠀⠀⢸⡇
⠀⠀⠈⢺⡿⠇⡀⠉⠉⠉⠉⢉⣼⡡⠋⠀⠀⢀⣴⠀⠀⣠⠟⠀
⠀⠀⠀⠀⢷⡀⢻⡶⣤⣤⠀⠀⠀⠀⣀⣤⡴⠛⡇⠀⠀⡏⠀⠀
⠀⠀⠀⠀⠈⠳⠼⠃⠀⠈⢧⡀⠀⠀⡇⠀⠀⠀⠻⣄⣀⡟⠀⠀도와줘... 도로롱...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠶⠾⠁⠀⠀⠀⠀⠈⠉⠀⠀⠀
*/

#include "net/rate_limiter.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <future>

using namespace std::chrono;
using boost::asio::awaitable;
using boost::asio::use_future;

namespace {

awaitable<int> drain(sps::net::RateLimiter& rl, int n) {
    for (int i = 0; i < n; ++i) co_await rl.acquire();
    co_return n;
}

} // namespace

TEST_CASE("RateLimiter: burst capacity drains immediately", "[rate_limiter]") {
    boost::asio::io_context io;
    sps::net::RateLimiter rl{io.get_executor(), /*rate*/100.0, /*cap*/50.0};

    auto fut = boost::asio::co_spawn(io, drain(rl, 50), use_future);
    const auto t0 = steady_clock::now();
    io.run();
    const auto elapsed = steady_clock::now() - t0;

    REQUIRE(fut.get() == 50);
    REQUIRE(elapsed < milliseconds(200));  // bucket 가득 → 거의 즉시
}

TEST_CASE("RateLimiter: over-capacity waits", "[rate_limiter]") {
    boost::asio::io_context io;
    sps::net::RateLimiter rl{io.get_executor(), /*rate*/100.0, /*cap*/10.0};

    auto fut = boost::asio::co_spawn(io, drain(rl, 30), use_future);
    const auto t0 = steady_clock::now();
    io.run();
    const auto elapsed = steady_clock::now() - t0;

    REQUIRE(fut.get() == 30);
    // 10 burst + 20 tokens @ 100/s = 200ms 최소
    REQUIRE(elapsed >= milliseconds(150));
}

TEST_CASE("RateLimiter: set_rate clamps to minimum", "[rate_limiter]") {
    boost::asio::io_context io;
    sps::net::RateLimiter rl{io.get_executor(), 100.0, 10.0};

    rl.set_rate(0.0);   // 무시돼야 함
    REQUIRE(rl.rate() >= 0.1);

    rl.set_rate(500.0);
    REQUIRE(rl.rate() == 500.0);
}

TEST_CASE("RateLimiter: concurrent acquirers share budget", "[rate_limiter]") {
    boost::asio::io_context io;
    sps::net::RateLimiter rl{io.get_executor(), /*rate*/200.0, /*cap*/5.0};

    // 3 코루틴이 각각 10개씩 = 총 30 요청.
    // 5 burst + 25 @ 200/s = ~125ms.
    auto f1 = boost::asio::co_spawn(io, drain(rl, 10), use_future);
    auto f2 = boost::asio::co_spawn(io, drain(rl, 10), use_future);
    auto f3 = boost::asio::co_spawn(io, drain(rl, 10), use_future);

    const auto t0 = steady_clock::now();
    io.run();
    const auto elapsed = steady_clock::now() - t0;

    REQUIRE(f1.get() == 10);
    REQUIRE(f2.get() == 10);
    REQUIRE(f3.get() == 10);
    REQUIRE(elapsed >= milliseconds(100));
    REQUIRE(elapsed <  milliseconds(500));  // 루즈 상한
}
