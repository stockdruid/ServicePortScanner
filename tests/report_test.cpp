#include "report/writers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <vector>

using sps::core::CveInfo;
using sps::core::PortState;
using sps::core::ScanResult;

namespace {

std::vector<ScanResult> sample() {
    ScanResult r;
    r.target_host = "127.0.0.1";
    r.port = 22;
    r.state = PortState::Open;
    r.service.name       = "ssh";
    r.service.version    = "OpenSSH_7.4";
    r.service.banner_raw = "SSH-2.0-OpenSSH_7.4\r\n";
    CveInfo c;
    c.cve_id     = "CVE-2018-15473";
    c.cvss_score = 5.3f;
    c.severity   = sps::core::severity_from_cvss(c.cvss_score);
    r.cves.push_back(std::move(c));
    return {r};
}

} // namespace

TEST_CASE("json round-trip parses", "[report]") {
    auto v = sample();
    auto json = sps::report::to_json(v);
    auto parsed = nlohmann::json::parse(json);
    REQUIRE(parsed.is_array());
    REQUIRE(parsed[0]["service"] == "ssh");
    REQUIRE(parsed[0]["cves"][0]["id"] == "CVE-2018-15473");
}

TEST_CASE("csv has header and row", "[report]") {
    auto v = sample();
    auto csv = sps::report::to_csv(v);
    REQUIRE(csv.find("host,port,state") != std::string::npos);
    REQUIRE(csv.find("127.0.0.1,22,open") != std::string::npos);
    REQUIRE(csv.find("CVE-2018-15473") != std::string::npos);
}

TEST_CASE("csv quotes fields with commas", "[report]") {
    ScanResult r;
    r.target_host = "h,with,commas";
    r.port = 1;
    r.state = PortState::Open;
    auto csv = sps::report::to_csv(std::vector<ScanResult>{r});
    REQUIRE(csv.find("\"h,with,commas\"") != std::string::npos);
}

TEST_CASE("html escapes injection attempts", "[report]") {
    ScanResult r;
    r.target_host = "<script>alert(1)</script>";
    r.port = 80;
    r.state = PortState::Open;
    r.service.name = "http";
    auto html = sps::report::to_html(std::vector<ScanResult>{r});
    REQUIRE(html.find("<script>alert") == std::string::npos);
    REQUIRE(html.find("&lt;script&gt;") != std::string::npos);
}
