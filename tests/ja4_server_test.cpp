// JA4S 핑거프린트 단위 테스트.

#include "fp/ja4_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

using sps::fp::compute_ja4s;
using sps::fp::Ja4SInput;
using sps::fp::parse_server_hello;

TEST_CASE("compute_ja4s — deterministic", "[ja4s]") {
    Ja4SInput a{};
    a.legacy_version = 0x0303;
    a.negotiated_version = 0x0304;
    a.cipher_id = 0x1301;  // TLS_AES_128_GCM_SHA256
    a.extension_types = {0x002b, 0x0033};
    a.alpn = "h2";

    REQUIRE(compute_ja4s(a) == compute_ja4s(a));
}

TEST_CASE("compute_ja4s — TLS 1.3 + h2 prefix", "[ja4s]") {
    Ja4SInput in{};
    in.legacy_version = 0x0303;
    in.negotiated_version = 0x0304;
    in.cipher_id = 0x1301;
    in.extension_types = {0x002b, 0x0033};
    in.alpn = "h2";

    const auto fp = compute_ja4s(in);
    // 형식: t13<count><alpn>_<cipher>_<hash>
    REQUIRE(fp.rfind("t1302h2_1301_", 0) == 0);
}

TEST_CASE("compute_ja4s — empty extensions zero hash", "[ja4s]") {
    Ja4SInput in{};
    in.legacy_version = 0x0303;
    in.cipher_id = 0xc02f;  // ECDHE-RSA-AES128-GCM-SHA256

    const auto fp = compute_ja4s(in);
    REQUIRE(fp.find("_000000000000") != std::string::npos);
}

TEST_CASE("compute_ja4s — alpn 1 char prepends 0", "[ja4s]") {
    Ja4SInput in{};
    in.legacy_version = 0x0303;
    in.cipher_id = 0x1301;
    in.alpn = "h";  // 1자 → "0h"
    REQUIRE(compute_ja4s(in).find("0h_1301_") != std::string::npos);
}

TEST_CASE("compute_ja4s — different ciphers differ", "[ja4s]") {
    Ja4SInput a{}; a.cipher_id = 0x1301;
    Ja4SInput b{}; b.cipher_id = 0x1303;
    REQUIRE(compute_ja4s(a) != compute_ja4s(b));
}

TEST_CASE("parse_server_hello — minimal TLS 1.3 message", "[ja4s]") {
    // ServerHello body 손수 조립.
    std::vector<std::uint8_t> body;
    auto u8  = [&](std::uint8_t v)  { body.push_back(v); };
    auto u16 = [&](std::uint16_t v) { u8(static_cast<std::uint8_t>(v >> 8));
                                      u8(static_cast<std::uint8_t>(v & 0xff)); };

    u16(0x0303);                   // legacy_version
    for (int i = 0; i < 32; ++i) u8(0xAB);  // random
    u8(0);                         // session_id_len = 0
    u16(0x1301);                   // cipher_suite
    u8(0);                         // compression_method

    // extensions: supported_versions(0x002b len=2 → 0x0304), key_share(0x0033 len=4 dummy).
    std::vector<std::uint8_t> exts;
    auto eu16 = [&](std::uint16_t v) {
        exts.push_back(static_cast<std::uint8_t>(v >> 8));
        exts.push_back(static_cast<std::uint8_t>(v & 0xff));
    };
    eu16(0x002b); eu16(0x0002); eu16(0x0304);
    eu16(0x0033); eu16(0x0004); eu16(0x001d); eu16(0x0001);

    u16(static_cast<std::uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    auto in = parse_server_hello(body.data(), body.size());
    REQUIRE(in.legacy_version == 0x0303);
    REQUIRE(in.negotiated_version == 0x0304);
    REQUIRE(in.cipher_id == 0x1301);
    REQUIRE(in.extension_types.size() == 2);
    REQUIRE(in.extension_types[0] == 0x002b);
    REQUIRE(in.extension_types[1] == 0x0033);
}

TEST_CASE("parse_server_hello — GREASE extensions excluded", "[ja4s]") {
    std::vector<std::uint8_t> body;
    auto u8  = [&](std::uint8_t v)  { body.push_back(v); };
    auto u16 = [&](std::uint16_t v) { u8(static_cast<std::uint8_t>(v >> 8));
                                      u8(static_cast<std::uint8_t>(v & 0xff)); };

    u16(0x0303);
    for (int i = 0; i < 32; ++i) u8(0);
    u8(0);
    u16(0x1301);
    u8(0);

    std::vector<std::uint8_t> exts;
    auto eu16 = [&](std::uint16_t v) {
        exts.push_back(static_cast<std::uint8_t>(v >> 8));
        exts.push_back(static_cast<std::uint8_t>(v & 0xff));
    };
    eu16(0x0a0a); eu16(0x0000);             // GREASE — 제외돼야
    eu16(0x002b); eu16(0x0002); eu16(0x0304);

    u16(static_cast<std::uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    auto in = parse_server_hello(body.data(), body.size());
    REQUIRE(in.extension_types.size() == 1);
    REQUIRE(in.extension_types[0] == 0x002b);
}

TEST_CASE("parse_server_hello — too short returns empty", "[ja4s]") {
    std::uint8_t junk[10] = {0};
    auto in = parse_server_hello(junk, sizeof(junk));
    REQUIRE(in.cipher_id == 0);
    REQUIRE(in.extension_types.empty());
}
