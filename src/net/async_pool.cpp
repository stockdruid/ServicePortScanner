#include "async_pool.hpp"

#include <spdlog/spdlog.h>

#include <exception>

namespace sps::net {

namespace {
constexpr std::size_t kDefaultThreads = 2;

std::size_t resolve_thread_count(std::size_t requested) {
    if (requested != 0) return requested;
    const auto hw = std::thread::hardware_concurrency();
    return hw == 0 ? kDefaultThreads : static_cast<std::size_t>(hw);
}
} // namespace

AsyncPool::AsyncPool(std::size_t thread_count)
    : io_{}
    , guard_{boost::asio::make_work_guard(io_)}
    , thread_count_{resolve_thread_count(thread_count)}
{}

AsyncPool::~AsyncPool() {
    // 소멸 경로 — hard-stop + join. restart/guard 재생성은 의미 없어 생략.
    if (!running_.load(std::memory_order_acquire)) return;
    guard_.reset();
    io_.stop();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
    running_.store(false, std::memory_order_release);
}

void AsyncPool::start() {
    if (running_.load(std::memory_order_acquire)) return;
    running_.store(true, std::memory_order_release);
    workers_.reserve(thread_count_);
    for (std::size_t i = 0; i < thread_count_; ++i) {
        workers_.emplace_back([this, i] {
            spdlog::debug("async_pool worker {} start", i);
            try {
                io_.run();
            } catch (const std::exception& e) {
                spdlog::error("async_pool worker {} uncaught: {}", i, e.what());
            } catch (...) {
                spdlog::error("async_pool worker {} unknown exception", i);
            }
            spdlog::debug("async_pool worker {} exit", i);
        });
    }
}

void AsyncPool::stop(bool force) {
    if (!running_.load(std::memory_order_acquire)) return;

    // graceful: 새 work 거부(guard 해제) → 진행 중인 핸들러 끝나면 run() 반환.
    // hard:     io.stop() 으로 대기 중인 타이머·async_wait 취소.
    guard_.reset();
    if (force) {
        io_.stop();
    }

    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();

    // 재시작 대비 — io_context 리셋.
    io_.restart();
    guard_ = boost::asio::make_work_guard(io_);
    running_.store(false, std::memory_order_release);
}

} // namespace sps::net
