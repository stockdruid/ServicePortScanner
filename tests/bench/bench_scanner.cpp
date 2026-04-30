// Scanner 벤치 — Stage 0.
//
// 측정 항목:
//  1. 단일 open port baseline (loopback RTT 하한).
//  2. N 개 open port 동시 스캔 throughput.
//  3. Closed port 지연 (Windows 는 RST, Linux 는 ICMP unreachable).

#include "core/scanner.hpp"
#include "mock_server.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <future>
#include <vector>

using namespace std::chrono;
using sps::core::connect_scan;
using sps::core::PortState;
using sps::core::ScanRequest;
using sps::core::ScanResult;

TEST_CASE("Scanner — single open port baseline", "[bench][scanner]") {
    sps::bench::MockServer server(1);
    const auto port = server.open_ports().front();

    BENCHMARK("connect_scan one open port (loopback)") {
        boost::asio::io_context io;
        auto fut = boost::asio::co_spawn(
            io.get_executor(),
            connect_scan(io.get_executor(),
                         ScanRequest{"127.0.0.1", port, milliseconds(500)}),
            boost::asio::use_future);
        io.run();
        return fut.get().state;
    };
}

TEST_CASE("Scanner — 50 open ports concurrent", "[bench][scanner]") {
    constexpr std::size_t N = 50;
    sps::bench::MockServer server(N);
    const auto ports = server.open_ports();
    REQUIRE(ports.size() == N);

    BENCHMARK("scan 50 open ports concurrently (single io_context)") {
        boost::asio::io_context io;
        std::vector<std::future<ScanResult>> futs;
        futs.reserve(ports.size());
        for (auto p : ports) {
            futs.push_back(boost::asio::co_spawn(
                io.get_executor(),
                connect_scan(io.get_executor(),
                             ScanRequest{"127.0.0.1", p, milliseconds(500)}),
                boost::asio::use_future));
        }
        io.run();
        std::size_t opened = 0;
        for (auto& f : futs) {
            if (f.get().state == PortState::Open) ++opened;
        }
        return opened;
    };
}

TEST_CASE("Scanner — 200 open ports concurrent", "[bench][scanner]") {
    constexpr std::size_t N = 200;
    sps::bench::MockServer server(N);
    const auto ports = server.open_ports();
    REQUIRE(ports.size() == N);

    BENCHMARK("scan 200 open ports concurrently") {
        boost::asio::io_context io;
        std::vector<std::future<ScanResult>> futs;
        futs.reserve(ports.size());
        for (auto p : ports) {
            futs.push_back(boost::asio::co_spawn(
                io.get_executor(),
                connect_scan(io.get_executor(),
                             ScanRequest{"127.0.0.1", p, milliseconds(500)}),
                boost::asio::use_future));
        }
        io.run();
        std::size_t opened = 0;
        for (auto& f : futs) {
            if (f.get().state == PortState::Open) ++opened;
        }
        return opened;
    };
}

TEST_CASE("Scanner — closed port latency", "[bench][scanner]") {
    BENCHMARK("connect_scan one closed loopback port") {
        boost::asio::io_context io;
        auto fut = boost::asio::co_spawn(
            io.get_executor(),
            connect_scan(io.get_executor(),
                         ScanRequest{"127.0.0.1", 1, milliseconds(500)}),
            boost::asio::use_future);
        io.run();
        return fut.get().state;
    };
}
