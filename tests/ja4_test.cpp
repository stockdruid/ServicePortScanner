#include "fp/ja4.hpp"

#include <catch2/catch_test_macros.hpp>

using sps::fp::compute_ja4;
using sps::fp::Ja4Input;

TEST_CASE("deterministic for same input", "[ja4]") {
    Ja4Input a{"TLSv1.3", "TLS_AES_128_GCM_SHA256", "h2"};
    REQUIRE(compute_ja4(a) == compute_ja4(a));
}

TEST_CASE("differs on different cipher", "[ja4]") {
    Ja4Input a{"TLSv1.3", "TLS_AES_128_GCM_SHA256", "h2"};
    Ja4Input b{"TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256", "h2"};
    REQUIRE(compute_ja4(a) != compute_ja4(b));
}

TEST_CASE("version tag prefix", "[ja4]") {
    Ja4Input v13{"TLSv1.3", "X", ""};
    Ja4Input v12{"TLSv1.2", "X", ""};
    REQUIRE(compute_ja4(v13).rfind("t13d_", 0) == 0);
    REQUIRE(compute_ja4(v12).rfind("t12d_", 0) == 0);
}
