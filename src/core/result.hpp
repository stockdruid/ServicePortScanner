#pragma once

// Unified ScanResult schema — 백엔드(CLI)와 GUI 양쪽이 공유하는 정본.
// 변경 이력: GUI MVP 레포(kimbjabgok/ServiceProtScanner_GuiMvp)의 풍부한
// ServiceInfo + CveInfo + 헬퍼 메서드 스키마로 통일.

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

enum class Severity : std::uint8_t {
    Critical,
    High,
    Medium,
    Low,
    None,
};

// CVSS 점수 → CVSS v3.1 등급 환산.
constexpr Severity severity_from_cvss(double cvss) noexcept {
    if (cvss >= 9.0) return Severity::Critical;
    if (cvss >= 7.0) return Severity::High;
    if (cvss >= 4.0) return Severity::Medium;
    if (cvss >  0.0) return Severity::Low;
    return Severity::None;
}

struct CveInfo {
    std::string cve_id;          // e.g. "CVE-2018-15473"
    std::string description;
    float       cvss_score{0};
    Severity    severity{Severity::None};
    double      epss{0};         // 0..1, 30-day exploit probability
    double      percentile{0};   // 0..1, EPSS percentile rank
    bool        nuclei_verified{false};
};

struct ServiceInfo {
    std::string name;            // e.g. "ssh"
    std::string product;         // e.g. "OpenSSH"
    std::string version;         // e.g. "7.4p1"
    std::string extra_info;
    std::string banner_raw;      // 원본 배너 (8KB cap)
};

struct ScanResult {
    std::string   target_host;
    std::string   resolved_ip;
    std::uint16_t port{0};
    std::string   protocol{"tcp"};
    PortState     state{PortState::Unknown};

    ServiceInfo service;

    std::string ja4s;            // FoxIO JA4S — TLS ServerHello fingerprint
    std::string ja4x;            // FoxIO JA4X — X.509 cert fingerprint
    std::string cdn;             // CDN/WAF provider tag, 비어있으면 미식별
    std::string os_guess;        // p0f-style OS guess (Stage 9)

    std::vector<CveInfo> cves;

    std::chrono::system_clock::time_point timestamp{};
    std::chrono::milliseconds rtt{0};

    [[nodiscard]] bool is_open() const noexcept {
        return state == PortState::Open;
    }

    [[nodiscard]] float max_cvss() const noexcept {
        float m = 0;
        for (const auto& c : cves) m = (c.cvss_score > m) ? c.cvss_score : m;
        return m;
    }

    [[nodiscard]] double max_epss() const noexcept {
        double m = 0;
        for (const auto& c : cves) m = (c.epss > m) ? c.epss : m;
        return m;
    }

    [[nodiscard]] double max_percentile() const noexcept {
        double m = 0;
        for (const auto& c : cves) m = (c.percentile > m) ? c.percentile : m;
        return m;
    }

    // Risk = CVSS × EPSS — 정렬 기본키.
    [[nodiscard]] double max_risk() const noexcept {
        double m = 0;
        for (const auto& c : cves) {
            const double risk = static_cast<double>(c.cvss_score) * c.epss;
            if (risk > m) m = risk;
        }
        return m;
    }

    [[nodiscard]] bool has_critical_cve() const noexcept {
        for (const auto& c : cves)
            if (c.severity == Severity::Critical) return true;
        return false;
    }

    [[nodiscard]] int verified_cve_count() const noexcept {
        int count = 0;
        for (const auto& c : cves)
            if (c.nuclei_verified) ++count;
        return count;
    }

    [[nodiscard]] bool has_verified_cve() const noexcept {
        return verified_cve_count() > 0;
    }
};

} // namespace sps::core
