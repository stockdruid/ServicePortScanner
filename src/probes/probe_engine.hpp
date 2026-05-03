#pragma once

// JSON-driven Probe — Stage 3 (Probe DB 외부화).
//
// 기존 SSH/FTP/SMTP/HTTP 4종 하드코딩 probe 를 선언적 규칙으로 대체.
// TLS 는 OpenSSL 핸드셰이크 특수성 때문에 네이티브 유지 (tls_probe.hpp).
//
// Stage 7: JsonProbe 클래스가 더 이상 가상 base 를 상속하지 않음. variant
// dispatch 의 한 alternative 로 사용됨 (probe_variant.hpp).

#include "probes/probe.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
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
    static ProbeDatabase load_default();
    static ProbeDatabase load_from_file(const std::string& path);
    static ProbeDatabase parse(std::string_view json_text);

    const std::vector<ProbeRule>& rules() const noexcept { return rules_; }
    std::size_t size() const noexcept { return rules_.size(); }
    bool empty() const noexcept { return rules_.empty(); }

private:
    std::vector<ProbeRule> rules_;
};

// JSON-rule 로 동작하는 probe — variant 의 한 alternative.
class JsonProbe {
public:
    explicit JsonProbe(ProbeRule rule) noexcept;

    std::string_view name() const noexcept;
    std::vector<std::uint16_t> hint_ports() const;

    boost::asio::awaitable<ProbeOutcome>
    identify(boost::asio::ip::tcp::socket& sock,
             std::chrono::milliseconds timeout) const;

private:
    ProbeRule rule_;
};

// DB 의 각 ProbeRule 을 JsonProbe 로 변환.
std::vector<JsonProbe> json_probes_from_database(const ProbeDatabase& db);

} // namespace sps::probes
