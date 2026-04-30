// Stage 10 — EpssDb 파서/룩업 검증.

#include "fp/epss_lookup.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <fstream>

using sps::fp::EpssDb;

TEST_CASE("EpssDb parses minimal CSV", "[epss]") {
    constexpr const char* csv =
        "#model_version:test\n"
        "cve,epss,percentile\n"
        "CVE-2018-15473,0.4512,0.9512\n"
        "CVE-2014-0160,0.9744,0.9993\n";

    auto db = EpssDb::parse(csv);
    REQUIRE(db.size() == 2);

    const auto a = db.lookup("CVE-2018-15473");
    REQUIRE(a.epss == Catch::Approx(0.4512));
    REQUIRE(a.percentile == Catch::Approx(0.9512));

    const auto b = db.lookup("CVE-2014-0160");
    REQUIRE(b.epss == Catch::Approx(0.9744));
}

TEST_CASE("EpssDb lookup case-insensitive", "[epss]") {
    auto db = EpssDb::parse("CVE-2014-0160,0.97,0.99\n");
    REQUIRE(db.lookup("cve-2014-0160").epss == Catch::Approx(0.97));
    REQUIRE(db.lookup("CVE-2014-0160").epss == Catch::Approx(0.97));
}

TEST_CASE("EpssDb miss returns zero entry", "[epss]") {
    auto db = EpssDb::parse("CVE-2014-0160,0.97,0.99\n");
    const auto miss = db.lookup("CVE-9999-9999");
    REQUIRE(miss.epss == 0.0);
    REQUIRE(miss.percentile == 0.0);
}

TEST_CASE("EpssDb skips comments and headers", "[epss]") {
    constexpr const char* csv =
        "#metadata\n"
        "cve,epss,percentile\n"
        "CVE-1-1,0.5,0.5\n";
    auto db = EpssDb::parse(csv);
    REQUIRE(db.size() == 1);
}

TEST_CASE("EpssDb skips malformed lines", "[epss]") {
    constexpr const char* csv =
        "CVE-OK,0.1,0.2\n"
        "garbage line\n"
        "CVE-BAD,not-a-number,0.5\n"
        "CVE-INCOMPLETE,0.3\n"
        "CVE-OK2,0.4,0.5\n";
    auto db = EpssDb::parse(csv);
    REQUIRE(db.size() == 2);
    REQUIRE(db.lookup("CVE-OK").epss == Catch::Approx(0.1));
    REQUIRE(db.lookup("CVE-OK2").epss == Catch::Approx(0.4));
}

TEST_CASE("EpssDb missing percentile defaults to 0", "[epss]") {
    auto db = EpssDb::parse("CVE-X-1,0.5,not-a-num\n");
    REQUIRE(db.size() == 1);
    REQUIRE(db.lookup("CVE-X-1").epss == Catch::Approx(0.5));
    REQUIRE(db.lookup("CVE-X-1").percentile == 0.0);
}

TEST_CASE("EpssDb empty input returns empty", "[epss]") {
    auto db = EpssDb::parse("");
    REQUIRE(db.empty());
}

TEST_CASE("EpssDb load from file round-trip", "[epss]") {
    const std::string path = "spscan_epss_test.csv";
    {
        std::ofstream f(path);
        f << "cve,epss,percentile\nCVE-Z-1,0.88,0.95\n";
    }
    auto db = EpssDb::load(path);
    std::remove(path.c_str());

    REQUIRE(db.size() == 1);
    REQUIRE(db.lookup("CVE-Z-1").epss == Catch::Approx(0.88));
}

TEST_CASE("EpssDb missing file returns empty", "[epss]") {
    auto db = EpssDb::load("/__nonexistent__/epss.csv");
    REQUIRE(db.empty());
}
