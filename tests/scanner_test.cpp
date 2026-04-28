#include "core/scanner.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <future>
#include <thread>

using boost::asio::ip::tcp;
using sps::core::connect_scan;
using sps::core::PortState;
using sps::core::ScanRequest;

namespace {

// 임시 listening socket 을 열어 실제로 connect 가 성공하는지 확인.
struct Listener {
    boost::asio::io_context io;
    tcp::acceptor acc{io, tcp::endpoint(tcp::v4(), 0)};
    std::thread th;
    std::uint16_t port() { return acc.local_endpoint().port(); }
    void start() {
        th = std::thread([this] {
            tcp::socket s(io);
            boost::system::error_code ec;
            acc.accept(s, ec);
        });
    }
    ~Listener() {
        boost::system::error_code ec;
        acc.close(ec);
        if (th.joinable()) th.join();
    }
};

} // namespace

TEST_CASE("connect_scan reports Open on listening port", "[scanner]") {
    Listener L;
    L.start();
    const auto port = L.port();

    boost::asio::io_context client_io;
    auto fut = boost::asio::co_spawn(
        client_io.get_executor(),
        connect_scan(client_io.get_executor(),
                     ScanRequest{"127.0.0.1", port,
                                 std::chrono::milliseconds(500)}),
        boost::asio::use_future);

    std::thread runner([&]{ client_io.run(); });
    auto r = fut.get();
    runner.join();

    REQUIRE(r.state == PortState::Open);
    REQUIRE(r.port == port);
}

TEST_CASE("connect_scan reports Closed for unused high port", "[scanner]") {
    boost::asio::io_context io;
    auto fut = boost::asio::co_spawn(
        io.get_executor(),
        connect_scan(io.get_executor(),
                     ScanRequest{"127.0.0.1", 1,  // port 1 거의 항상 닫힘
                                 std::chrono::milliseconds(500)}),
        boost::asio::use_future);
    std::thread runner([&]{ io.run(); });
    auto r = fut.get();
    runner.join();
    // closed 또는 filtered (OS firewall 환경에 따라).
    REQUIRE((r.state == PortState::Closed || r.state == PortState::Filtered));
}
