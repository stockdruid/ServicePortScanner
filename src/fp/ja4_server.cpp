#include "fp/ja4_server.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace sps::fp {

namespace {

std::string sha256_hex(std::string_view data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    EVP_MD_CTX_free(ctx);
    std::ostringstream ss;
    for (unsigned int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(digest[i]);
    }
    return ss.str();
}

std::string version_tag(std::uint16_t v) {
    switch (v) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    default:     return "00";
    }
}

std::string alpn_tag(std::string_view a) {
    if (a.empty()) return "00";
    if (a.size() == 1) {
        return std::string("0") + a.front();
    }
    return std::string{a.front()} + std::string{a.back()};
}

bool is_grease(std::uint16_t v) {
    const auto hi = static_cast<std::uint8_t>(v >> 8);
    const auto lo = static_cast<std::uint8_t>(v & 0xff);
    return (hi == lo) && ((lo & 0x0f) == 0x0a);
}

std::string two_digits(std::size_t n) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02zu", std::min<std::size_t>(n, 99));
    return std::string(buf);
}

std::string four_hex(std::uint16_t v) {
    char buf[5];
    std::snprintf(buf, sizeof(buf), "%04x", v);
    return std::string(buf);
}

} // namespace

Ja4SInput parse_server_hello(const std::uint8_t* p, std::size_t len) {
    Ja4SInput in{};
    // 최소 길이: legacy_version(2) + random(32) + sid_len(1) + 0 + cipher(2) + comp(1) + ext_len(2) = 40
    if (!p || len < 40) return in;

    auto take_u8 = [&](std::uint8_t& out) {
        if (len < 1) return false;
        out = p[0]; p += 1; len -= 1; return true;
    };
    auto take_u16 = [&](std::uint16_t& out) {
        if (len < 2) return false;
        out = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
        p += 2; len -= 2; return true;
    };
    auto skip = [&](std::size_t n) {
        if (len < n) return false;
        p += n; len -= n; return true;
    };

    if (!take_u16(in.legacy_version)) return {};
    if (!skip(32)) return {};

    std::uint8_t sid_len = 0;
    if (!take_u8(sid_len)) return {};
    if (!skip(sid_len)) return {};

    if (!take_u16(in.cipher_id)) return {};

    std::uint8_t compression = 0;
    if (!take_u8(compression)) return {};

    std::uint16_t ext_total = 0;
    if (!take_u16(ext_total)) return {};
    if (len < ext_total) return {};

    // 확장 리스트 — ext_total 바이트만 보고 남은 바이트는 무시.
    std::size_t off = 0;
    while (off + 4 <= ext_total) {
        const std::uint16_t et = static_cast<std::uint16_t>((p[off] << 8) | p[off + 1]);
        const std::uint16_t el = static_cast<std::uint16_t>((p[off + 2] << 8) | p[off + 3]);
        if (off + 4 + el > ext_total) break;

        if (!is_grease(et)) {
            in.extension_types.push_back(et);
        }

        // supported_versions in ServerHello: type 0x002b, 2-byte body = chosen version.
        if (et == 0x002b && el == 2) {
            in.negotiated_version = static_cast<std::uint16_t>(
                (p[off + 4] << 8) | p[off + 5]);
        }

        off += 4 + el;
    }

    return in;
}

std::string compute_ja4s(const Ja4SInput& in) {
    const std::uint16_t v = in.negotiated_version
        ? in.negotiated_version
        : in.legacy_version;

    const std::string proto = in.over_quic ? "q" : "t";
    const std::string ver   = version_tag(v);
    const std::string count = two_digits(in.extension_types.size());
    const std::string alpn  = alpn_tag(in.alpn);
    const std::string ciph  = four_hex(in.cipher_id);

    std::string ext_joined;
    for (auto et : in.extension_types) {
        if (!ext_joined.empty()) ext_joined += ',';
        ext_joined += four_hex(et);
    }
    const std::string ext_hash = ext_joined.empty()
        ? std::string("000000000000")
        : sha256_hex(ext_joined).substr(0, 12);

    return proto + ver + count + alpn + "_" + ciph + "_" + ext_hash;
}

} // namespace sps::fp
