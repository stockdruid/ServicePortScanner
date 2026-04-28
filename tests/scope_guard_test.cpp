#include "cli/scope_guard.hpp"

#include <catch2/catch_test_macros.hpp>

using sps::cli::check_scope;
using sps::cli::ScopeDecision;

TEST_CASE("loopback always allowed", "[scope]") {
    REQUIRE(check_scope("127.0.0.1", {}) == ScopeDecision::Allowed);
    REQUIRE(check_scope("::1",       {}) == ScopeDecision::Allowed);
}

TEST_CASE("RFC1918 ranges allowed without consent", "[scope]") {
    REQUIRE(check_scope("10.0.0.5",      {}) == ScopeDecision::Allowed);
    REQUIRE(check_scope("172.16.0.1",    {}) == ScopeDecision::Allowed);
    REQUIRE(check_scope("172.31.255.254",{}) == ScopeDecision::Allowed);
    REQUIRE(check_scope("192.168.1.1",   {}) == ScopeDecision::Allowed);
}

TEST_CASE("172.32+ is NOT private", "[scope]") {
    REQUIRE(check_scope("172.32.0.1", {}) ==
            ScopeDecision::DeniedExternalNeedsConsent);
}

TEST_CASE("external IP requires consent", "[scope]") {
    REQUIRE(check_scope("8.8.8.8", {})
            == ScopeDecision::DeniedExternalNeedsConsent);
    REQUIRE(check_scope("8.8.8.8", {true})
            == ScopeDecision::Allowed);
}

TEST_CASE("invalid address rejected", "[scope]") {
    REQUIRE(check_scope("not-an-ip", {})
            == ScopeDecision::DeniedInvalidAddress);
    REQUIRE(check_scope("999.999.999.999", {})
            == ScopeDecision::DeniedInvalidAddress);
}
