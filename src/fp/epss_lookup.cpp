#include "fp/epss_lookup.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <sstream>

namespace sps::fp {

namespace {

std::string to_upper(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                          s.front() == '\r' || s.front() == '\n')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                          s.back() == '\r' || s.back() == '\n')) {
        s.remove_suffix(1);
    }
    return s;
}

bool parse_double(std::string_view s, double& out) {
    if (s.empty()) return false;
    // <charconv> std::from_chars(double) 는 일부 stdlib 미지원 → strtod 사용.
    std::string buf(s);
    char* end = nullptr;
    const double v = std::strtod(buf.c_str(), &end);
    if (end == buf.c_str()) return false;
    out = v;
    return true;
}

// "CVE-2018-15473" 같은 형식 검증 (느슨하게: "CVE-" 접두 + 길이 7+).
bool looks_like_cve(std::string_view s) {
    if (s.size() < 7) return false;
    if (!(s[0] == 'C' || s[0] == 'c')) return false;
    if (!(s[1] == 'V' || s[1] == 'v')) return false;
    if (!(s[2] == 'E' || s[2] == 'e')) return false;
    return s[3] == '-';
}

} // namespace

EpssDb EpssDb::parse(std::string_view csv_text) {
    EpssDb db;
    if (csv_text.empty()) return db;

    std::size_t line_start = 0;
    while (line_start < csv_text.size()) {
        const auto nl = csv_text.find('\n', line_start);
        const auto end = (nl == std::string_view::npos) ? csv_text.size() : nl;
        const auto line = trim(csv_text.substr(line_start, end - line_start));
        line_start = end + 1;

        if (line.empty()) continue;
        if (line.front() == '#') continue;          // 메타 코멘트
        if (!looks_like_cve(line)) continue;        // header "cve,epss,..." 자동 스킵

        // 3-column split.
        const auto c1 = line.find(',');
        if (c1 == std::string_view::npos) continue;
        const auto c2 = line.find(',', c1 + 1);
        if (c2 == std::string_view::npos) continue;

        const auto cve = line.substr(0, c1);
        const auto epss_s = line.substr(c1 + 1, c2 - c1 - 1);
        const auto pct_s = line.substr(c2 + 1);

        Entry e;
        if (!parse_double(epss_s, e.epss)) continue;
        if (!parse_double(pct_s, e.percentile)) {
            // percentile 결손은 허용 (0 으로 둠).
            e.percentile = 0.0;
        }
        db.map_.emplace(to_upper(cve), e);
    }
    return db;
}

EpssDb EpssDb::load(const std::filesystem::path& csv_path) {
    std::ifstream f(csv_path);
    if (!f) return {};
    std::ostringstream oss;
    oss << f.rdbuf();
    return parse(oss.str());
}

EpssDb::Entry EpssDb::lookup(std::string_view cve_id) const {
    const auto it = map_.find(to_upper(cve_id));
    if (it == map_.end()) return {};
    return it->second;
}

} // namespace sps::fp
