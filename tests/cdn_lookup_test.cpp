// Stage 5 — CdnDatabase parser/lookup 검증.

#include "fp/cdn_lookup.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <fstream>

using sps::fp::CdnDatabase;

TEST_CASE("CdnDatabase loads embedded default", "[cdn]") {
    auto db = CdnDatabase::load_default();
    REQUIRE(db.size() > 30);  // ~50 entries
}

TEST_CASE("CdnDatabase identifies Cloudflare 1.1.1.1", "[cdn]") {
    auto db = CdnDatabase::load_default();
    REQUIRE(db.lookup("1.1.1.1") == "cloudflare");
    REQUIRE(db.lookup("1.0.0.1") == "cloudflare");
    REQUIRE(db.lookup("104.16.0.1") == "cloudflare");
}

TEST_CASE("CdnDatabase identifies Fastly 151.101.x", "[cdn]") {
    auto db = CdnDatabase::load_default();
    REQUIRE(db.lookup("151.101.65.69") == "fastly");
}

TEST_CASE("CdnDatabase non-CDN address returns empty", "[cdn]") {
    auto db = CdnDatabase::load_default();
    REQUIRE(db.lookup("127.0.0.1").empty());
    REQUIRE(db.lookup("192.168.1.1").empty());
    REQUIRE(db.lookup("10.0.0.1").empty());
    REQUIRE(db.lookup("8.8.8.8").empty());  // Google DNS, not in default DB
}

TEST_CASE("CdnDatabase malformed IPv4 returns empty", "[cdn]") {
    auto db = CdnDatabase::load_default();
    REQUIRE(db.lookup("not.an.ip").empty());
    REQUIRE(db.lookup("1.2.3").empty());
    REQUIRE(db.lookup("1.2.3.4.5").empty());
    REQUIRE(db.lookup("256.0.0.0").empty());
    REQUIRE(db.lookup("").empty());
}

TEST_CASE("CdnDatabase parses minimal JSON", "[cdn]") {
    constexpr const char* json = R"({
        "version": 1,
        "ranges": [
            { "cidr": "10.0.0.0/8", "provider": "test-net" }
        ]
    })";
    auto db = CdnDatabase::parse(json);
    REQUIRE(db.size() == 1);
    REQUIRE(db.lookup("10.5.5.5") == "test-net");
    REQUIRE(db.lookup("11.0.0.0").empty());
}

TEST_CASE("CdnDatabase skips invalid CIDR entries", "[cdn]") {
    constexpr const char* json = R"({
        "version": 1,
        "ranges": [
            { "cidr": "not-a-cidr", "provider": "bad" },
            { "cidr": "10.0.0.0/33", "provider": "out-of-range" },
            { "cidr": "10.0.0.0/24", "provider": "good" }
        ]
    })";
    auto db = CdnDatabase::parse(json);
    REQUIRE(db.size() == 1);
    REQUIRE(db.lookup("10.0.0.5") == "good");
}

TEST_CASE("CdnDatabase rejects malformed JSON", "[cdn]") {
    auto db = CdnDatabase::parse("garbage{{{");
    REQUIRE(db.empty());
}

TEST_CASE("CdnDatabase load_from_file round-trip", "[cdn]") {
    const std::string path = "spscan_cdn_test_db.json";
    {
        std::ofstream f(path);
        f << R"({"version":1,"ranges":[
            {"cidr":"172.16.0.0/12","provider":"x"}
        ]})";
    }
    auto db = CdnDatabase::load_from_file(path);
    std::remove(path.c_str());

    REQUIRE(db.size() == 1);
    REQUIRE(db.lookup("172.20.5.5") == "x");
}

TEST_CASE("CdnDatabase missing file returns empty", "[cdn]") {
    auto db = CdnDatabase::load_from_file("/__nonexistent__/cdn.json");
    REQUIRE(db.empty());
}

TEST_CASE("CdnDatabase /32 single-host entry", "[cdn]") {
    auto db = CdnDatabase::parse(R"({
        "version": 1,
        "ranges": [{"cidr":"203.0.113.5/32","provider":"single"}]
    })");
    REQUIRE(db.lookup("203.0.113.5") == "single");
    REQUIRE(db.lookup("203.0.113.6").empty());
}
