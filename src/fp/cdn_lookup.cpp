#include "fp/cdn_lookup.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>

namespace sps::fp {

namespace {

// 임베디드 기본 DB. 출처:
//   Cloudflare    : https://www.cloudflare.com/ips-v4/
//   Fastly        : https://api.fastly.com/public-ip-list
//   AWS CloudFront: https://ip-ranges.amazonaws.com/ip-ranges.json (CLOUDFRONT 서브셋)
//   Imperva       : https://docs.imperva.com/bundle/cloud-application-security/page/more/whitelist.htm
// 주의: 정기 갱신 필요. 발표 시점 기준 스냅샷.
constexpr std::string_view kDefaultDb = R"json(
{
  "version": 1,
  "ranges": [
    { "cidr": "1.0.0.0/24",        "provider": "cloudflare" },
    { "cidr": "1.1.1.0/24",        "provider": "cloudflare" },
    { "cidr": "103.21.244.0/22",   "provider": "cloudflare" },
    { "cidr": "103.22.200.0/22",   "provider": "cloudflare" },
    { "cidr": "103.31.4.0/22",     "provider": "cloudflare" },
    { "cidr": "104.16.0.0/13",     "provider": "cloudflare" },
    { "cidr": "104.24.0.0/14",     "provider": "cloudflare" },
    { "cidr": "108.162.192.0/18",  "provider": "cloudflare" },
    { "cidr": "131.0.72.0/22",     "provider": "cloudflare" },
    { "cidr": "141.101.64.0/18",   "provider": "cloudflare" },
    { "cidr": "162.158.0.0/15",    "provider": "cloudflare" },
    { "cidr": "172.64.0.0/13",     "provider": "cloudflare" },
    { "cidr": "173.245.48.0/20",   "provider": "cloudflare" },
    { "cidr": "188.114.96.0/20",   "provider": "cloudflare" },
    { "cidr": "190.93.240.0/20",   "provider": "cloudflare" },
    { "cidr": "197.234.240.0/22",  "provider": "cloudflare" },
    { "cidr": "198.41.128.0/17",   "provider": "cloudflare" },

    { "cidr": "23.235.32.0/20",    "provider": "fastly" },
    { "cidr": "43.249.72.0/22",    "provider": "fastly" },
    { "cidr": "103.244.50.0/24",   "provider": "fastly" },
    { "cidr": "103.245.222.0/23",  "provider": "fastly" },
    { "cidr": "104.156.80.0/20",   "provider": "fastly" },
    { "cidr": "146.75.0.0/16",     "provider": "fastly" },
    { "cidr": "151.101.0.0/16",    "provider": "fastly" },
    { "cidr": "157.52.64.0/18",    "provider": "fastly" },
    { "cidr": "167.82.0.0/17",     "provider": "fastly" },
    { "cidr": "172.111.64.0/18",   "provider": "fastly" },
    { "cidr": "185.31.16.0/22",    "provider": "fastly" },
    { "cidr": "199.27.72.0/21",    "provider": "fastly" },
    { "cidr": "199.232.0.0/16",    "provider": "fastly" },

    { "cidr": "13.32.0.0/15",      "provider": "aws-cloudfront" },
    { "cidr": "13.224.0.0/14",     "provider": "aws-cloudfront" },
    { "cidr": "52.84.0.0/15",      "provider": "aws-cloudfront" },
    { "cidr": "54.182.0.0/16",     "provider": "aws-cloudfront" },
    { "cidr": "54.192.0.0/16",     "provider": "aws-cloudfront" },
    { "cidr": "54.230.0.0/16",     "provider": "aws-cloudfront" },
    { "cidr": "54.239.128.0/18",   "provider": "aws-cloudfront" },
    { "cidr": "99.84.0.0/16",      "provider": "aws-cloudfront" },
    { "cidr": "204.246.164.0/22",  "provider": "aws-cloudfront" },
    { "cidr": "205.251.192.0/19",  "provider": "aws-cloudfront" },

    { "cidr": "23.32.0.0/11",      "provider": "akamai" },
    { "cidr": "23.192.0.0/11",     "provider": "akamai" },
    { "cidr": "104.64.0.0/10",     "provider": "akamai" },
    { "cidr": "184.24.0.0/13",     "provider": "akamai" },

    { "cidr": "199.83.128.0/21",   "provider": "imperva" },
    { "cidr": "198.143.32.0/19",   "provider": "imperva" },
    { "cidr": "149.126.72.0/21",   "provider": "imperva" },
    { "cidr": "103.28.248.0/22",   "provider": "imperva" },
    { "cidr": "185.11.124.0/22",   "provider": "imperva" },
    { "cidr": "192.230.64.0/18",   "provider": "imperva" }
  ]
}
)json";

bool parse_ipv4(std::string_view s, std::uint32_t& out) {
    std::uint32_t v = 0;
    int parts = 0;
    std::size_t i = 0;
    while (i < s.size() && parts < 4) {
        std::uint32_t octet = 0;
        std::size_t digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            octet = octet * 10 + static_cast<std::uint32_t>(s[i] - '0');
            ++i;
            ++digits;
            if (digits > 3 || octet > 255) return false;
        }
        if (digits == 0) return false;
        v = (v << 8) | octet;
        ++parts;
        if (parts < 4) {
            if (i >= s.size() || s[i] != '.') return false;
            ++i;
        }
    }
    if (parts != 4 || i != s.size()) return false;
    out = v;
    return true;
}

bool parse_cidr(std::string_view s, std::uint32_t& base, std::uint32_t& mask) {
    const auto slash = s.find('/');
    if (slash == std::string_view::npos) return false;
    if (!parse_ipv4(s.substr(0, slash), base)) return false;
    const auto prefix_str = s.substr(slash + 1);
    if (prefix_str.empty() || prefix_str.size() > 2) return false;
    int prefix = 0;
    for (const auto c : prefix_str) {
        if (c < '0' || c > '9') return false;
        prefix = prefix * 10 + (c - '0');
    }
    if (prefix < 0 || prefix > 32) return false;
    mask = (prefix == 0) ? 0u
                          : static_cast<std::uint32_t>(~0u) << (32 - prefix);
    base &= mask;
    return true;
}

} // namespace

CdnDatabase CdnDatabase::parse(std::string_view json_text) {
    CdnDatabase db;
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_text);
    } catch (const nlohmann::json::parse_error&) {
        return db;
    }
    if (!j.contains("ranges") || !j["ranges"].is_array()) return db;
    for (const auto& rj : j["ranges"]) {
        if (!rj.contains("cidr") || !rj.contains("provider")) continue;
        if (!rj["cidr"].is_string() || !rj["provider"].is_string()) continue;
        const auto cidr = rj["cidr"].get<std::string>();
        Range r;
        if (!parse_cidr(cidr, r.base, r.mask)) continue;
        r.provider = rj["provider"].get<std::string>();
        db.ranges_.push_back(std::move(r));
    }
    return db;
}

CdnDatabase CdnDatabase::load_default() {
    return parse(kDefaultDb);
}

CdnDatabase CdnDatabase::load_from_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::ostringstream oss;
    oss << in.rdbuf();
    return parse(oss.str());
}

std::string CdnDatabase::lookup(std::string_view ipv4) const {
    std::uint32_t addr = 0;
    if (!parse_ipv4(ipv4, addr)) return {};
    for (const auto& r : ranges_) {
        if ((addr & r.mask) == r.base) {
            return r.provider;
        }
    }
    return {};
}

} // namespace sps::fp
