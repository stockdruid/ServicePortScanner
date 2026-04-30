#pragma once

// JA4S — TLS ServerHello 핑거프린트 (FoxIO JA4+ 스펙).
//
// 서버 스캐너에 의미 있는 신호: 서버 TLS 스택의 ServerHello 배열·alpn·cipher 패턴.
// 형식:  <protocol><tls_ver><ext_count><alpn>_<cipher_hex>_<extensions_hash>
//
//   protocol  : 't' (TCP) | 'q' (QUIC)
//   tls_ver   : 13/12/11/10/s3/00 (negotiated, supported_versions ext 우선)
//   ext_count : ServerHello 확장 개수 2-digit (max 99)
//   alpn      : 협상된 ALPN 의 첫+끝 문자, 1자 면 "0X", 없으면 "00"
//   cipher    : 협상 cipher RFC ID 4-digit lowercase hex
//   ext_hash  : 확장 type 들 (GREASE 제외, ServerHello 순서 유지)
//               4-hex 문자열 콤마 join → SHA-256 → 앞 12 chars
//
// 참고: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sps::fp {

struct Ja4SInput {
    bool over_quic = false;
    std::uint16_t legacy_version = 0;       // ServerHello legacy_version field
    std::uint16_t negotiated_version = 0;   // supported_versions ext 가 있을 때 우선
    std::uint16_t cipher_id = 0;            // RFC IANA cipher ID (16-bit)
    std::vector<std::uint16_t> extension_types;  // ServerHello 순서, GREASE 제외
    std::string alpn;                        // 협상된 ALPN (예: "h2", "http/1.1")
};

std::string compute_ja4s(const Ja4SInput& in);

// ServerHello body (4-byte handshake header 제외) 를 파싱해 Ja4SInput 채움.
// cipher_id / legacy_version / extension_types / negotiated_version 만 채워짐.
// over_quic / alpn 은 호출자가 별도 설정.
// 실패 시 빈 input 반환 (extension_types 가 비어있고 cipher_id == 0).
Ja4SInput parse_server_hello(const std::uint8_t* data, std::size_t len);

} // namespace sps::fp
