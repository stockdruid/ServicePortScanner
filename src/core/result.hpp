#pragma once

// TEMP stub — Core Scanner 담당자가 최종 정의할 구조체.
// Async Engine 은 이 POD 에만 의존하므로 먼저 placeholder 로 진행.

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace sps::core {

enum class PortState : std::uint8_t {
    Open,
    Closed,
    Filtered,
    Unknown,
};

struct CveHit {
    std::string id;       // e.g. "CVE-2018-15473"
    double      cvss = 0; // 0.0 ~ 10.0
};

struct ScanResult {
    std::string host;
    std::uint16_t port = 0;
    PortState state = PortState::Unknown;
    std::string service;
    std::string version;
    std::string banner;
    std::string ja4;     // legacy/MVP server fingerprint (Stage 4 이후 ja4s 권장)
    std::string ja4s;    // FoxIO JA4S — TLS ServerHello fingerprint
    std::string ja4x;    // FoxIO JA4X — X.509 cert fingerprint
    std::string cdn;     // CDN/WAF provider tag (Stage 5), 비어있으면 미식별
    std::vector<CveHit> cves;
    std::chrono::steady_clock::time_point completed_at{};
};

} // namespace sps::core
