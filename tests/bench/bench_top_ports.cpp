// Top-Ports 벤치 — Stage 0.
//
// 측정 항목:
//  1. top_n_ports() 테이블 lookup 비용 (무시 가능해야).
//  2. top-100 vs port range 1-256 스캔 시간 비교.
//     리스너 없는 호스트 기준이라 모든 포트가 Closed/Filtered 로 끝남 →
//     "포트 개수 자체" 가 시간에 미치는 영향만 본다.

#include "cli/top_ports.hpp"
#include "core/scanner.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <future>
#include <vector>

using namespace std::chrono;
using sps::cli::top_n_ports;
using sps::core::connect_scan;
using sps::core::ScanRequest;
using sps::core::ScanResult;

TEST_CASE("top_n_ports — table lookup", "[bench][top_ports]") {
    BENCHMARK("top_n_ports(100) copy") {
        return top_n_ports(100);
    };

    BENCHMARK("top_n_ports(20) copy") {
        return top_n_ports(20);
    };
}

namespace {

void scan_ports(const std::vector<std::uint16_t>& ports) {
    boost::asio::io_context io;
    std::vector<std::future<ScanResult>> futs;
    futs.reserve(ports.size());
    for (auto p : ports) {
        futs.push_back(boost::asio::co_spawn(
            io.get_executor(),
            connect_scan(io.get_executor(),
                         ScanRequest{"127.0.0.1", p, milliseconds(200)}),
            boost::asio::use_future));
    }
    io.run();
    for (auto& f : futs) (void)f.get();
}

} // namespace

TEST_CASE("Scan top-100 vs range 1-256 (loopback, no listeners)",
          "[bench][top_ports]") {
    const auto top100 = top_n_ports(100);

    std::vector<std::uint16_t> range_1_256;
    range_1_256.reserve(256);
    for (std::uint16_t p = 1; p <= 256; ++p) range_1_256.push_back(p);

    BENCHMARK("scan top-100") {
        scan_ports(top100);
        return top100.size();
    };

    BENCHMARK("scan port range 1-256") {
        scan_ports(range_1_256);
        return range_1_256.size();
    };
}
