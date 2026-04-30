#pragma once

// JSON-driven Probe — Stage 3 (Probe DB 외부화).
//
// 기존 SSH/FTP/SMTP/HTTP 4종 하드코딩 probe 를 선언적 규칙으로 대체.
// TLS 는 OpenSSL 핸드셰이크 특수성 때문에 네이티브 유지 (tls_probe.cpp).
//
// 스키마 (data/probes.json):
//   {
//     "version": 1,
//     "probes": [
//       {
//         "name": "ssh",
//         "rarity": 6,
//         "ports": [22, 2222],
//         "send": "",                  // 빈 문자열 = passive (read-only)
//         "match": [
//           { "regex": "^SSH-\\d+\\.\\d+-([^\\r\\n]+)",
//             "service": "ssh", "version": "$1" }
//         ]
//       }
//     ]
//   }
//
// 새 프로토콜 추가: data/probes.json 항목 1개 추가, 컴파일 불필요.
// 외부 파일 미지정 시 임베디드 기본 DB 사용 → 단일 바이너리 시연 보장.

#include "probes/probe.hpp"

#include <cstdint>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace sps::probes {

struct MatchRule {
    std::regex re;
    std::string raw_pattern;
    std::string service_template;   // 리터럴 또는 $1..$9
    std::string version_template;   // 리터럴 또는 $1..$9
};

struct ProbeRule {
    std::string name;
    int rarity = 5;
    std::vector<std::uint16_t> ports;
    std::string send_payload;       // 빈 = passive, 비어있지 않음 = active
    std::vector<MatchRule> matches; // 첫 매칭이 승.
};

class ProbeDatabase {
public:
    // 임베디드 기본 DB (ssh/ftp/smtp/http) 로드.
    static ProbeDatabase load_default();

    // 파일 경로에서 로드. 실패 → 빈 DB (호출자가 폴백 결정).
    static ProbeDatabase load_from_file(const std::string& path);

    // JSON 문자열 직접 파싱. 잘못된 항목은 스킵, 유효한 항목만 적재.
    static ProbeDatabase parse(std::string_view json_text);

    const std::vector<ProbeRule>& rules() const noexcept { return rules_; }
    std::size_t size() const noexcept { return rules_.size(); }
    bool empty() const noexcept { return rules_.empty(); }

private:
    std::vector<ProbeRule> rules_;
};

// DB 의 각 ProbeRule 을 Probe 인터페이스로 래핑.
std::vector<ProbePtr> probes_from_database(const ProbeDatabase& db);

} // namespace sps::probes
