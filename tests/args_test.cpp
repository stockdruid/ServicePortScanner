#include "cli/args.hpp"

#include <catch2/catch_test_macros.hpp>

using sps::cli::expand_port_spec;

TEST_CASE("single port", "[args]") {
    auto v = expand_port_spec("443");
    REQUIRE(v == std::vector<std::uint16_t>{443});
}

TEST_CASE("range port", "[args]") {
    auto v = expand_port_spec("80-82");
    REQUIRE(v == (std::vector<std::uint16_t>{80, 81, 82}));
}

TEST_CASE("mixed list", "[args]") {
    auto v = expand_port_spec("22,80-82,443");
    REQUIRE(v == (std::vector<std::uint16_t>{22, 80, 81, 82, 443}));
}

TEST_CASE("dedupe", "[args]") {
    auto v = expand_port_spec("80,80,80");
    REQUIRE(v.size() == 1);
}

TEST_CASE("reversed range normalized", "[args]") {
    auto v = expand_port_spec("85-80");
    REQUIRE(v.size() == 6);
    REQUIRE(v.front() == 80);
    REQUIRE(v.back()  == 85);
}

TEST_CASE("invalid spec rejected", "[args]") {
    REQUIRE(expand_port_spec("abc").empty());
    REQUIRE(expand_port_spec("0").empty());        // 0 invalid
    REQUIRE(expand_port_spec("70000").empty());    // > 65535
    REQUIRE(expand_port_spec("80,abc").empty());
}
