#pragma once

// JA4-style 핑거프린트 (서버 측, MVP 근사).
//
// 주의: 본 구현은 정식 JA4 스펙의 단순화 버전이다.
// 정식 JA4_S 는 ServerHello raw 바이트를 직접 파싱하여 cipher list,
// extension 순서 등 다중 필드를 결합한다. 본 코드는 OpenSSL 후처리 정보
// (negotiated TLS version, cipher name, ALPN) 만 사용해 SHA-256 truncate
// 를 적용한 동등 형식의 식별자를 생성한다.
//
// 형식: t<ver_major><ver_minor>d_<cipher_short>_<alpn_truncated>

#include <string>
#include <string_view>

namespace sps::fp {

struct Ja4Input {
    std::string tls_version;  // e.g. "TLSv1.3"
    std::string cipher;       // e.g. "TLS_AES_128_GCM_SHA256"
    std::string alpn;         // e.g. "h2", "http/1.1", or ""
};

std::string compute_ja4(const Ja4Input& in);

} // namespace sps::fp
