// Stage 7 — ScanResult 할당 프로파일.
//
// 측정 항목:
//  1. ScanResult 기본 생성 (state/port 만 채움) × 1000
//  2. ScanResult + ServiceInfo 문자열 5개 채움 × 1000
//  3. ScanResult + N CVE 푸시 (1, 3, 10) × 1000
//  4. CveDb::lookup 직접 호출 (실제 hot path)
//
// 베이스라인 vs cve_lookup 두-패스 reserve 후 비교용.
// 결과는 효율성 개선 연구 자료 §4 (자원 효율) 참조.

#include "core/result.hpp"
#include "fp/cve_lookup.hpp"

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace {

using sps::core::CveInfo;
using sps::core::PortState;
using sps::core::ScanResult;
using sps::core::ServiceInfo;
using sps::core::Severity;

ScanResult make_empty(int port_offset) {
    ScanResult r;
    r.target_host = "127.0.0.1";
    r.port = static_cast<std::uint16_t>(80 + port_offset);
    r.state = PortState::Closed;
    return r;
}

ScanResult make_with_service(int port_offset) {
    auto r = make_empty(port_offset);
    r.state = PortState::Open;
    r.service.name       = "http";
    r.service.product    = "nginx";
    r.service.version    = "1.18.0";
    r.service.extra_info = "Ubuntu";
    r.service.banner_raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0";
    return r;
}

CveInfo make_cve(int i) {
    CveInfo c;
    c.cve_id      = "CVE-2021-" + std::to_string(40000 + i);
    c.description = "Sample vulnerability description for benchmarking";
    c.cvss_score  = 7.5f;
    c.severity    = Severity::High;
    c.epss        = 0.42;
    c.percentile  = 0.85;
    return c;
}

ScanResult make_with_cves(int port_offset, int cve_count) {
    auto r = make_with_service(port_offset);
    for (int i = 0; i < cve_count; ++i) r.cves.push_back(make_cve(i));
    return r;
}

constexpr const char* kCveJson = R"({
  "openssh": [
    { "version_prefix": "7.4",   "id": "CVE-2018-15473", "cvss": 5.3 },
    { "version_prefix": "7.4",   "id": "CVE-2017-15906", "cvss": 5.3 },
    { "version_prefix": "7.4",   "id": "CVE-2016-10708", "cvss": 7.5 },
    { "version_prefix": "8.0",   "id": "CVE-2019-6109",  "cvss": 6.8 }
  ],
  "nginx": [
    { "version_prefix": "1.18",  "id": "CVE-2021-23017", "cvss": 9.4 },
    { "version_prefix": "1.18",  "id": "CVE-2019-9511",  "cvss": 7.5 },
    { "version_prefix": "1.18",  "id": "CVE-2019-9513",  "cvss": 7.5 }
  ]
})";

} // namespace

TEST_CASE("AllocProfile: ScanResult basic construction",
          "[bench][alloc_profile]") {
    BENCHMARK("default ScanResult (port + state only) x 1000") {
        std::vector<ScanResult> v;
        v.reserve(1000);
        for (int i = 0; i < 1000; ++i) v.emplace_back(make_empty(i));
        return v.size();
    };

    BENCHMARK("ScanResult + ServiceInfo populated x 1000") {
        std::vector<ScanResult> v;
        v.reserve(1000);
        for (int i = 0; i < 1000; ++i) v.emplace_back(make_with_service(i));
        return v.size();
    };
}

TEST_CASE("AllocProfile: cves vector growth cost",
          "[bench][alloc_profile]") {
    BENCHMARK("ScanResult + 1 CVE x 1000") {
        std::vector<ScanResult> v;
        v.reserve(1000);
        for (int i = 0; i < 1000; ++i) v.emplace_back(make_with_cves(i, 1));
        return v.size();
    };

    BENCHMARK("ScanResult + 3 CVEs x 1000") {
        std::vector<ScanResult> v;
        v.reserve(1000);
        for (int i = 0; i < 1000; ++i) v.emplace_back(make_with_cves(i, 3));
        return v.size();
    };

    BENCHMARK("ScanResult + 10 CVEs x 1000") {
        std::vector<ScanResult> v;
        v.reserve(1000);
        for (int i = 0; i < 1000; ++i) v.emplace_back(make_with_cves(i, 10));
        return v.size();
    };
}

TEST_CASE("AllocProfile: CveDb::lookup hot path",
          "[bench][alloc_profile]") {
    auto db = sps::fp::CveDb::load_from_string(kCveJson);
    REQUIRE(db.size() == 7);

    BENCHMARK("lookup nginx 1.18 (3 hits) x 1000") {
        std::size_t total = 0;
        for (int i = 0; i < 1000; ++i) {
            auto hits = db.lookup("nginx", "nginx/1.18.0");
            total += hits.size();
        }
        return total;
    };

    BENCHMARK("lookup openssh 7.4 (3 hits) x 1000") {
        std::size_t total = 0;
        for (int i = 0; i < 1000; ++i) {
            auto hits = db.lookup("openssh", "OpenSSH_7.4p1");
            total += hits.size();
        }
        return total;
    };

    BENCHMARK("lookup miss x 1000") {
        std::size_t total = 0;
        for (int i = 0; i < 1000; ++i) {
            auto hits = db.lookup("unknown", "0.0.0");
            total += hits.size();
        }
        return total;
    };
}
