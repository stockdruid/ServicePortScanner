#include "fp/cve_lookup.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace sps::fp {

namespace {

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

// version "OpenSSH_7.4p1" 안에 "7.4" prefix 가 들어있는지.
bool version_matches(std::string_view version, std::string_view prefix) {
    if (prefix.empty()) return false;
    return version.find(prefix) != std::string_view::npos;
}

} // namespace

CveDb CveDb::load(const std::filesystem::path& json_path) {
    std::ifstream f(json_path);
    if (!f) return {};
    std::ostringstream buf;
    buf << f.rdbuf();
    return load_from_string(buf.str());
}

CveDb CveDb::load_from_string(std::string_view json_text) {
    CveDb db;
    if (json_text.empty()) return db;

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_text);
    } catch (...) {
        return db;
    }
    if (!j.is_object()) return db;

    for (auto it = j.begin(); it != j.end(); ++it) {
        const std::string svc = to_lower(it.key());
        if (!it.value().is_array()) continue;
        for (const auto& item : it.value()) {
            if (!item.is_object()) continue;
            Entry e;
            e.service_lower = svc;
            e.version_prefix = item.value("version_prefix", "");
            e.id = item.value("id", "");
            e.cvss = item.value("cvss", 0.0);
            if (!e.id.empty() && !e.version_prefix.empty()) {
                db.entries_.push_back(std::move(e));
            }
        }
    }
    return db;
}

std::vector<sps::core::CveInfo>
CveDb::lookup(std::string_view service, std::string_view version) const {
    std::vector<sps::core::CveInfo> hits;
    if (service.empty() || version.empty()) return hits;
    const std::string svc = to_lower(service);

    // Stage 7: 두-패스 — 정확히 한 번 만 alloc.
    // 첫 패스에서 매칭 카운트 → reserve → 두 번째 패스에서 push.
    // entries_ 는 보통 수십 개 수준이라 cache 에 머물러 추가 traverse 비용 무시.
    std::size_t count = 0;
    for (const auto& e : entries_) {
        if (e.service_lower != svc) continue;
        if (!version_matches(version, e.version_prefix)) continue;
        ++count;
    }
    if (count == 0) return hits;
    hits.reserve(count);

    for (const auto& e : entries_) {
        if (e.service_lower != svc) continue;
        if (!version_matches(version, e.version_prefix)) continue;
        sps::core::CveInfo hit;
        hit.cve_id     = e.id;
        hit.cvss_score = static_cast<float>(e.cvss);
        hit.severity   = sps::core::severity_from_cvss(e.cvss);
        hits.push_back(std::move(hit));
    }
    return hits;
}

} // namespace sps::fp
