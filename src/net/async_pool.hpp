#pragma once

// Async Engine — 단일 io_context + N개 워커 스레드.
//
// 설계:
//  - io_context 1개를 여러 thread 가 run() → 이벤트 자동 분산.
//  - work_guard 로 유휴 상태에서도 run() 유지 (수동 종료 전까지).
//  - stop() 은 graceful(기본) 또는 hard(force=true) 선택.
//    graceful: guard 해제 후 pending 완료되면 run() 자연 종료.
//    hard:     io.stop() 호출로 즉시 중단, 대기 중 핸들러는 cancelled.
//  - RAII: dtor 에서 hard-stop + join (누수·데드락 방지).
//
// 사용 예:
//   sps::net::AsyncPool pool{4};
//   pool.start();
//   auto fut = pool.spawn([&]() -> awaitable<int> { co_return 42; });
//   pool.stop();  // graceful

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <cstddef>
#include <future>
#include <thread>
#include <vector>

namespace sps::net {

class AsyncPool {
public:
    explicit AsyncPool(std::size_t thread_count = 0);  // 0 = hardware_concurrency
    ~AsyncPool();

    AsyncPool(const AsyncPool&)            = delete;
    AsyncPool& operator=(const AsyncPool&) = delete;
    AsyncPool(AsyncPool&&)                 = delete;
    AsyncPool& operator=(AsyncPool&&)      = delete;

    void start();
    void stop(bool force = false);  // false = graceful, true = hard

    bool running() const noexcept { return running_; }
    std::size_t thread_count() const noexcept { return thread_count_; }

    boost::asio::io_context& context() noexcept { return io_; }
    boost::asio::any_io_executor executor() { return io_.get_executor(); }

    // 편의: 코루틴 스폰 → future 반환.
    template <class Awaitable>
    auto spawn(Awaitable&& a) {
        return boost::asio::co_spawn(
            io_.get_executor(),
            std::forward<Awaitable>(a),
            boost::asio::use_future);
    }

private:
    boost::asio::io_context io_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard_;
    std::vector<std::thread> workers_;
    std::size_t thread_count_;
    bool running_ = false;
};

} // namespace sps::net
