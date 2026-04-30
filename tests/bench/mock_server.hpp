#pragma once

// MockServer — 다수의 임시 listening 소켓을 127.0.0.1 에 열어두는 헬퍼.
//
// 모든 accept 는 즉시 socket 을 drop 한다 → connect_scan 입장에선 Open 으로 판정.
// 포트는 OS 가 0 으로 바인딩 시 자동 할당하므로, open_ports() 로 실제 번호를 받는다.
//
// 단일 io_context + 단일 스레드. 벤치 한 회마다 새 인스턴스를 만들 필요 없이
// 외부 (예: TEST_CASE) 에서 한 번 만들어두고 BENCHMARK 본문에서 재사용한다.

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

namespace sps::bench {

class MockServer {
public:
    using tcp = boost::asio::ip::tcp;

    explicit MockServer(std::size_t n_ports) {
        acceptors_.reserve(n_ports);
        for (std::size_t i = 0; i < n_ports; ++i) {
            auto a = std::make_shared<tcp::acceptor>(
                io_,
                tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
            a->listen();
            do_accept(a);
            acceptors_.push_back(std::move(a));
        }
        thread_ = std::thread([this] { io_.run(); });
    }

    ~MockServer() {
        guard_.reset();
        boost::system::error_code ec;
        for (auto& a : acceptors_) a->close(ec);
        io_.stop();
        if (thread_.joinable()) thread_.join();
    }

    MockServer(const MockServer&) = delete;
    MockServer& operator=(const MockServer&) = delete;

    std::vector<std::uint16_t> open_ports() const {
        std::vector<std::uint16_t> p;
        p.reserve(acceptors_.size());
        for (const auto& a : acceptors_) {
            p.push_back(a->local_endpoint().port());
        }
        return p;
    }

private:
    void do_accept(std::shared_ptr<tcp::acceptor> a) {
        auto self = a;
        a->async_accept(
            [this, self](boost::system::error_code ec, tcp::socket s) {
                if (ec) return;
                (void)s;
                do_accept(self);
            });
    }

    boost::asio::io_context io_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
        guard_{io_.get_executor()};
    std::vector<std::shared_ptr<tcp::acceptor>> acceptors_;
    std::thread thread_;
};

} // namespace sps::bench
