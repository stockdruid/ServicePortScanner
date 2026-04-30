// JA4X 핑거프린트 단위 테스트.

#include "fp/ja4_x509.hpp"

#include <catch2/catch_test_macros.hpp>

using sps::fp::compute_ja4x;
using sps::fp::Ja4XInput;

TEST_CASE("compute_ja4x — deterministic for same OIDs", "[ja4x]") {
    Ja4XInput a;
    a.issuer_oids  = {"2.5.4.6", "2.5.4.10", "2.5.4.3"};
    a.subject_oids = {"2.5.4.6", "2.5.4.3"};
    a.ext_oids     = {"2.5.29.15", "2.5.29.37", "2.5.29.17"};

    REQUIRE(compute_ja4x(a) == compute_ja4x(a));
}

TEST_CASE("compute_ja4x — different OID order gives different hash", "[ja4x]") {
    Ja4XInput a;
    a.issuer_oids  = {"2.5.4.6", "2.5.4.10"};
    a.subject_oids = {"2.5.4.3"};

    Ja4XInput b;
    b.issuer_oids  = {"2.5.4.10", "2.5.4.6"};  // 순서 반대
    b.subject_oids = {"2.5.4.3"};

    REQUIRE(compute_ja4x(a) != compute_ja4x(b));
}

TEST_CASE("compute_ja4x — empty fields default to zeros", "[ja4x]") {
    Ja4XInput empty;
    const auto fp = compute_ja4x(empty);
    REQUIRE(fp == "000000000000_000000000000_000000000000");
}

TEST_CASE("compute_ja4x — three underscore-separated 12-char hashes",
          "[ja4x]") {
    Ja4XInput a;
    a.issuer_oids  = {"2.5.4.6"};
    a.subject_oids = {"2.5.4.3"};
    a.ext_oids     = {"2.5.29.15"};

    const auto fp = compute_ja4x(a);
    // 12 + 1 + 12 + 1 + 12 = 38
    REQUIRE(fp.size() == 38);
    REQUIRE(fp[12] == '_');
    REQUIRE(fp[25] == '_');
}
