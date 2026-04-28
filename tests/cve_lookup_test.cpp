#include "fp/cve_lookup.hpp"

#include <catch2/catch_test_macros.hpp>

using sps::fp::CveDb;

namespace {

constexpr const char* kJson = R"({
  "openssh": [
    { "version_prefix": "7.4", "id": "CVE-2018-15473", "cvss": 5.3 }
  ],
  "vsftpd": [
    { "version_prefix": "2.3.4", "id": "CVE-2011-2523", "cvss": 9.8 }
  ]
})";

} // namespace

TEST_CASE("empty json yields empty db", "[cve]") {
    REQUIRE(CveDb::load_from_string("").empty());
    REQUIRE(CveDb::load_from_string("not json").empty());
}

TEST_CASE("matches by version prefix substring", "[cve]") {
    auto db = CveDb::load_from_string(kJson);
    REQUIRE(db.size() == 2);
    auto hits = db.lookup("openssh", "OpenSSH_7.4p1");
    REQUIRE(hits.size() == 1);
    REQUIRE(hits[0].id == "CVE-2018-15473");
    REQUIRE(hits[0].cvss == 5.3);
}

TEST_CASE("case-insensitive service", "[cve]") {
    auto db = CveDb::load_from_string(kJson);
    REQUIRE(db.lookup("OPENSSH", "OpenSSH_7.4").size() == 1);
}

TEST_CASE("no false match", "[cve]") {
    auto db = CveDb::load_from_string(kJson);
    REQUIRE(db.lookup("openssh", "OpenSSH_8.0").empty());
    REQUIRE(db.lookup("nonexistent", "1.0").empty());
}
