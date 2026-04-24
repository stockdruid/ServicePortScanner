#include "net/async_pool.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>

using namespace std::chrono;
using boost::asio::awaitable;
using boost::asio::use_awaitable;

TEST_CASE("AsyncPool: start/stop clean (graceful)", "[async_pool]") {
    sps::net::AsyncPool pool{2};
    pool.start();
    REQUIRE(pool.running());
    pool.stop();
    REQUIRE_FALSE(pool.running());
}

TEST_CASE("AsyncPool: start is idempotent", "[async_pool]") {
    sps::net::AsyncPool pool{2};
    pool.start();
    pool.start();  // 두 번째는 no-op 이어야 함
    REQUIRE(pool.running());
    pool.stop();
}

TEST_CASE("AsyncPool: coroutine runs to completion", "[async_pool]") {
    sps::net::AsyncPool pool{2};
    pool.start();

    std::atomic<int> ran{0};
    auto fut = pool.spawn([&ran]() -> awaitable<int> {
        auto exec = co_await boost::asio::this_coro::executor;
        boost::asio::steady_timer t{exec};
        t.expires_after(milliseconds(10));
        co_await t.async_wait(use_awaitable);
        ran.store(1);
        co_return 42;
    });

    REQUIRE(fut.get() == 42);
    REQUIRE(ran.load() == 1);
    pool.stop();
}

TEST_CASE("AsyncPool: many coroutines run in parallel", "[async_pool]") {
    sps::net::AsyncPool pool{4};
    pool.start();

    constexpr int N = 100;
    std::atomic<int> done{0};
    std::vector<std::future<int>> futs;
    futs.reserve(N);

    for (int i = 0; i < N; ++i) {
        futs.push_back(pool.spawn([&done, i]() -> awaitable<int> {
            auto exec = co_await boost::asio::this_coro::executor;
            boost::asio::steady_timer t{exec};
            t.expires_after(milliseconds(5));
            co_await t.async_wait(use_awaitable);
            done.fetch_add(1);
            co_return i;
        }));
    }

    int sum = 0;
    for (auto& f : futs) sum += f.get();

    REQUIRE(done.load() == N);
    REQUIRE(sum == N * (N - 1) / 2);
    pool.stop();
}

TEST_CASE("AsyncPool: restart after stop", "[async_pool]") {
    sps::net::AsyncPool pool{2};

    pool.start();
    auto f1 = pool.spawn([]() -> awaitable<int> { co_return 1; });
    REQUIRE(f1.get() == 1);
    pool.stop();

    pool.start();
    auto f2 = pool.spawn([]() -> awaitable<int> { co_return 2; });
    REQUIRE(f2.get() == 2);
    pool.stop();
}

TEST_CASE("AsyncPool: hard stop cancels pending timer", "[async_pool]") {
    sps::net::AsyncPool pool{1};
    pool.start();

    std::atomic<bool> completed{false};
    pool.spawn([&completed]() -> awaitable<void> {
        auto exec = co_await boost::asio::this_coro::executor;
        boost::asio::steady_timer t{exec};
        t.expires_after(seconds(10));  // 오래 걸림 — 강제 종료로 끊어야 함
        boost::system::error_code ec;
        co_await t.async_wait(boost::asio::redirect_error(use_awaitable, ec));
        completed.store(true);
    });

    const auto t0 = steady_clock::now();
    pool.stop(/*force=*/true);
    const auto elapsed = steady_clock::now() - t0;

    REQUIRE(elapsed < seconds(1));  // 10초 타이머 무시하고 즉시 종료
}
