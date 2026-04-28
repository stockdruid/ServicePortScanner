#include "fp/ja4.hpp"

#include <openssl/evp.h>

#include <array>
#include <cstdint>
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

std::string version_tag(std::string_view ver) {
    if (ver == "TLSv1.3") return "13";
    if (ver == "TLSv1.2") return "12";
    if (ver == "TLSv1.1") return "11";
    if (ver == "TLSv1.0") return "10";
    return "00";
}

} // namespace

std::string compute_ja4(const Ja4Input& in) {
    const std::string canonical =
        in.tls_version + "|" + in.cipher + "|" + in.alpn;
    const std::string hash = sha256_hex(canonical);
    const std::string short_hash = hash.empty() ? "" : hash.substr(0, 12);
    return "t" + version_tag(in.tls_version) + "d_" + short_hash +
           "_" + (in.alpn.empty() ? "00" : in.alpn);
}

} // namespace sps::fp
