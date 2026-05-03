#include "probes/probe_engine.hpp"
#include "probes/banner_io.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <utility>

namespace sps::probes {

namespace {

// 임베디드 기본 DB. data/probes.json 과 동일 내용을 raw string 으로 보관.
// 외부 파일이 없거나 파싱 실패 시 폴백 → 단일 바이너리 시연 보장.
constexpr std::string_view kDefaultDb = R"json(
{
  "version": 1,
  "probes": [
    {
      "name": "ssh",
      "rarity": 6,
      "ports": [22, 2222],
      "send": "",
      "match": [
        { "regex": "^SSH-\\d+\\.\\d+-([^\\r\\n]+)",
          "service": "ssh",
          "version": "$1" }
      ]
    },
    {
      "name": "ftp",
      "rarity": 7,
      "ports": [21],
      "send": "",
      "match": [
        { "regex": "^220[\\s\\S]*?((?:vsFTPd|ProFTPD|FileZilla|Pure-FTPd)[\\s/]?[\\d.\\w-]+)",
          "service": "ftp",
          "version": "$1" },
        { "regex": "^220",
          "service": "ftp",
          "version": "" }
      ]
    },
    {
      "name": "smtp",
      "rarity": 7,
      "ports": [25, 465, 587],
      "send": "",
      "match": [
        { "regex": "^220[\\s\\S]*?((?:Postfix|Sendmail|Exim|Microsoft ESMTP|qmail)[\\s/]?[\\d.\\w-]*)",
          "service": "smtp",
          "version": "$1" },
        { "regex": "^220",
          "service": "smtp",
          "version": "" }
      ]
    },
    {
      "name": "http",
      "rarity": 8,
      "ports": [80, 8080, 8000, 8888],
      "send": "OPTIONS / HTTP/1.0\r\nUser-Agent: spscan/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
      "match": [
        { "regex": "^HTTP/[0-9.]+[\\s\\S]*?Server:\\s*([^\\r\\n]+)",
          "service": "http",
          "version": "$1" },
        { "regex": "^HTTP/",
          "service": "http",
          "version": "" }
      ]
    }
  ]
}
)json";

// $0..$9 backreference 치환. $0 = 전체 매치. 인식 안 되는 $X 는 그대로.
std::string apply_template(const std::string& tpl, const std::smatch& m) {
    if (tpl.empty()) return {};
    std::string out;
    out.reserve(tpl.size());
    for (std::size_t i = 0; i < tpl.size(); ++i) {
        if (tpl[i] == '$' && i + 1 < tpl.size()
            && tpl[i + 1] >= '0' && tpl[i + 1] <= '9') {
            const std::size_t idx = static_cast<std::size_t>(tpl[i + 1] - '0');
            if (idx < m.size()) out += m[idx].str();
            ++i;
            continue;
        }
        out += tpl[i];
    }
    return out;
}

// JsonProbe 클래스는 probe_engine.hpp 에 선언. 여기는 method 구현.

bool parse_match(const nlohmann::json& j, MatchRule& out) {
    if (!j.contains("regex") || !j["regex"].is_string()) return false;
    out.raw_pattern = j["regex"].get<std::string>();
    try {
        out.re = std::regex(out.raw_pattern,
                             std::regex::ECMAScript | std::regex::icase);
    } catch (const std::regex_error&) {
        return false;
    }
    if (j.contains("service") && j["service"].is_string()) {
        out.service_template = j["service"].get<std::string>();
    }
    if (j.contains("version") && j["version"].is_string()) {
        out.version_template = j["version"].get<std::string>();
    }
    return true;
}

bool parse_probe(const nlohmann::json& j, ProbeRule& out) {
    if (!j.contains("name") || !j["name"].is_string()) return false;
    if (!j.contains("match") || !j["match"].is_array()) return false;

    out.name = j["name"].get<std::string>();
    if (j.contains("rarity") && j["rarity"].is_number_integer()) {
        out.rarity = j["rarity"].get<int>();
    }
    if (j.contains("send") && j["send"].is_string()) {
        out.send_payload = j["send"].get<std::string>();
    }
    if (j.contains("ports") && j["ports"].is_array()) {
        for (const auto& p : j["ports"]) {
            if (!p.is_number_unsigned()) continue;
            const auto v = p.get<unsigned>();
            if (v >= 1 && v <= 65535) {
                out.ports.push_back(static_cast<std::uint16_t>(v));
            }
        }
    }
    for (const auto& mj : j["match"]) {
        MatchRule mr;
        if (parse_match(mj, mr)) out.matches.push_back(std::move(mr));
    }
    return !out.matches.empty();
}

} // namespace

ProbeDatabase ProbeDatabase::parse(std::string_view json_text) {
    ProbeDatabase db;
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_text);
    } catch (const nlohmann::json::parse_error&) {
        return db;
    }
    if (!j.contains("probes") || !j["probes"].is_array()) return db;
    for (const auto& pj : j["probes"]) {
        ProbeRule rule;
        if (parse_probe(pj, rule)) db.rules_.push_back(std::move(rule));
    }
    return db;
}

ProbeDatabase ProbeDatabase::load_default() {
    return parse(kDefaultDb);
}

ProbeDatabase ProbeDatabase::load_from_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::ostringstream oss;
    oss << in.rdbuf();
    return parse(oss.str());
}

// ===== JsonProbe method 구현 =====

JsonProbe::JsonProbe(ProbeRule rule) noexcept : rule_{std::move(rule)} {}

std::string_view JsonProbe::name() const noexcept { return rule_.name; }

std::vector<std::uint16_t> JsonProbe::hint_ports() const { return rule_.ports; }

boost::asio::awaitable<ProbeOutcome>
JsonProbe::identify(boost::asio::ip::tcp::socket& sock,
                    std::chrono::milliseconds timeout) const {
    ProbeOutcome out;

    if (!rule_.send_payload.empty()) {
        const bool wrote = co_await detail::write_all(
            sock, rule_.send_payload, timeout);
        if (!wrote) co_return out;
    }

    std::string banner;
    const bool read = co_await detail::read_until_quiet(
        sock, banner, timeout, kMaxBannerBytes);
    if (!read || banner.empty()) co_return out;

    for (const auto& mr : rule_.matches) {
        std::smatch m;
        if (!std::regex_search(banner, m, mr.re)) continue;
        out.matched = true;
        out.service = apply_template(mr.service_template, m);
        out.version = apply_template(mr.version_template, m);
        out.banner = banner.substr(
            0, std::min<std::size_t>(banner.size(), 1024));
        co_return out;
    }
    co_return out;
}

std::vector<JsonProbe> json_probes_from_database(const ProbeDatabase& db) {
    std::vector<JsonProbe> out;
    out.reserve(db.size());
    for (const auto& rule : db.rules()) {
        out.emplace_back(rule);
    }
    return out;
}

} // namespace sps::probes
