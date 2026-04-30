#pragma once

// JA4X — 서버 X.509 인증서 핑거프린트 (FoxIO JA4+ 스펙).
//
// 형식: <issuer_oid_hash>_<subject_oid_hash>_<extensions_oid_hash>
//   각 hash = SHA-256(콤마-join 된 OID dotted decimal 문자열) 의 앞 12 chars
//
// MVP 주의: 정식 스펙은 OID 의 DER hex 바이트를 사용한다. 본 구현은 dotted
//          decimal 문자열을 사용하므로 결정성·식별 가능성은 동일하나 외부
//          DB(JA4X DB) 와 직접 매칭되지 않을 수 있다. Stage 4+ 강화 대상.
//
// 참고: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.md

#include <string>
#include <vector>

// OpenSSL 의 X509 는 `typedef struct x509_st X509;` 형태.
// 헤더 무게를 줄이려고 풀 include 대신 전역 namespace 에 forward decl.
struct x509_st;

namespace sps::fp {

struct Ja4XInput {
    std::vector<std::string> issuer_oids;   // RDN 순서 유지
    std::vector<std::string> subject_oids;  // RDN 순서 유지
    std::vector<std::string> ext_oids;      // X.509 확장 순서 유지
};

std::string compute_ja4x(const Ja4XInput& in);

// OpenSSL 의 X509* 에서 issuer/subject/extension OID 들을 dotted decimal 로 추출.
Ja4XInput extract_ja4x_input(::x509_st* cert);

} // namespace sps::fp
