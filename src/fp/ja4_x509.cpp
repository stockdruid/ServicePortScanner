#include "fp/ja4_x509.hpp"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <array>
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

std::string hash_or_default(const std::vector<std::string>& oids) {
    if (oids.empty()) return std::string("000000000000");
    std::string joined;
    for (const auto& o : oids) {
        if (!joined.empty()) joined += ',';
        joined += o;
    }
    const auto h = sha256_hex(joined);
    return h.empty() ? std::string("000000000000") : h.substr(0, 12);
}

void extract_name_oids(X509_NAME* name, std::vector<std::string>& dst) {
    if (!name) return;
    const int n = X509_NAME_entry_count(name);
    for (int i = 0; i < n; ++i) {
        X509_NAME_ENTRY* e = X509_NAME_get_entry(name, i);
        if (!e) continue;
        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(e);
        if (!obj) continue;
        char buf[128];
        const int len = OBJ_obj2txt(buf, sizeof(buf), obj, /*always_numeric*/ 1);
        if (len > 0 && static_cast<std::size_t>(len) < sizeof(buf)) {
            dst.emplace_back(buf, static_cast<std::size_t>(len));
        }
    }
}

} // namespace

Ja4XInput extract_ja4x_input(::x509_st* cert) {
    Ja4XInput out;
    if (!cert) return out;

    extract_name_oids(X509_get_issuer_name(cert), out.issuer_oids);
    extract_name_oids(X509_get_subject_name(cert), out.subject_oids);

    const int n = X509_get_ext_count(cert);
    for (int i = 0; i < n; ++i) {
        X509_EXTENSION* ext = X509_get_ext(cert, i);
        if (!ext) continue;
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        if (!obj) continue;
        char buf[128];
        const int len = OBJ_obj2txt(buf, sizeof(buf), obj, /*always_numeric*/ 1);
        if (len > 0 && static_cast<std::size_t>(len) < sizeof(buf)) {
            out.ext_oids.emplace_back(buf, static_cast<std::size_t>(len));
        }
    }
    return out;
}

std::string compute_ja4x(const Ja4XInput& in) {
    return hash_or_default(in.issuer_oids) + "_"
         + hash_or_default(in.subject_oids) + "_"
         + hash_or_default(in.ext_oids);
}

} // namespace sps::fp
