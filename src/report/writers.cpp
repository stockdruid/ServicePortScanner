#include "report/writers.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace sps::report {

namespace {

std::string state_str(sps::core::PortState s) {
    using S = sps::core::PortState;
    switch (s) {
        case S::Open:     return "open";
        case S::Closed:   return "closed";
        case S::Filtered: return "filtered";
        case S::Unknown:  return "unknown";
    }
    return "unknown";
}

// HTML 엔티티 이스케이프. raw concat 금지 규칙.
std::string escape_html(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

std::string escape_csv_field(std::string_view in) {
    bool quote = in.find_first_of(",\"\n\r") != std::string_view::npos;
    if (!quote) return std::string(in);
    std::string out;
    out.reserve(in.size() + 2);
    out.push_back('"');
    for (char c : in) {
        if (c == '"') out.push_back('"');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

} // namespace

std::string to_json(std::span<const sps::core::ScanResult> results) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& r : results) {
        nlohmann::json item;
        item["host"] = r.target_host;
        item["port"] = r.port;
        item["state"] = state_str(r.state);
        item["service"] = r.service.name;
        item["product"] = r.service.product;
        item["version"] = r.service.version;
        item["banner"] = r.service.banner_raw;
        item["ja4s"] = r.ja4s;
        item["ja4x"] = r.ja4x;
        item["cdn"] = r.cdn;
        item["os_guess"] = r.os_guess;
        nlohmann::json cves = nlohmann::json::array();
        for (const auto& c : r.cves) {
            // risk = CVSS × EPSS — 발표·정렬용 파생값.
            const double risk = static_cast<double>(c.cvss_score) * c.epss;
            cves.push_back({
                {"id", c.cve_id},
                {"cvss", c.cvss_score},
                {"epss", c.epss},
                {"percentile", c.percentile},
                {"risk", risk},
                {"nuclei_verified", c.nuclei_verified}
            });
        }
        item["cves"] = std::move(cves);
        arr.push_back(std::move(item));
    }
    return arr.dump(2);
}

std::string to_csv(std::span<const sps::core::ScanResult> results) {
    std::ostringstream ss;
    ss << "host,port,state,service,version,top_cve,top_cvss\n";
    for (const auto& r : results) {
        std::string top_id;
        float top_cvss = 0;
        for (const auto& c : r.cves) {
            if (c.cvss_score > top_cvss) { top_cvss = c.cvss_score; top_id = c.cve_id; }
        }
        ss << escape_csv_field(r.target_host) << ','
           << r.port << ','
           << state_str(r.state) << ','
           << escape_csv_field(r.service.name) << ','
           << escape_csv_field(r.service.version) << ','
           << escape_csv_field(top_id) << ','
           << top_cvss << '\n';
    }
    return ss.str();
}

std::string to_html(std::span<const sps::core::ScanResult> results) {
    std::ostringstream ss;
    ss << "<!doctype html><html><head><meta charset='utf-8'>"
          "<title>spscan report</title>"
          "<style>"
          "body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:24px}"
          "table{border-collapse:collapse;width:100%}"
          "th,td{padding:6px 10px;border-bottom:1px solid #333;text-align:left;font-size:13px}"
          "tr.crit{background:#5a1f1f}tr.high{background:#5a3a1f}tr.med{background:#4a4a1f}"
          "</style></head><body>"
          "<h1>spscan report</h1>"
          "<table><thead><tr>"
          "<th>host</th><th>port</th><th>state</th><th>service</th>"
          "<th>version</th><th>top CVE</th><th>CVSS</th>"
          "</tr></thead><tbody>";
    for (const auto& r : results) {
        std::string top_id;
        float top_cvss = 0;
        for (const auto& c : r.cves) {
            if (c.cvss_score > top_cvss) { top_cvss = c.cvss_score; top_id = c.cve_id; }
        }
        const char* row_class =
            (top_cvss >= 9.0f) ? "crit" :
            (top_cvss >= 7.0f) ? "high" :
            (top_cvss >= 4.0f) ? "med"  : "";
        ss << "<tr class='" << row_class << "'>"
           << "<td>" << escape_html(r.target_host) << "</td>"
           << "<td>" << r.port << "</td>"
           << "<td>" << state_str(r.state) << "</td>"
           << "<td>" << escape_html(r.service.name) << "</td>"
           << "<td>" << escape_html(r.service.version) << "</td>"
           << "<td>" << escape_html(top_id) << "</td>"
           << "<td>" << top_cvss << "</td>"
           << "</tr>";
    }
    ss << "</tbody></table></body></html>";
    return ss.str();
}

bool write_to_file(const std::string& path, const std::string& content) {
    if (path.empty()) {
        std::cout << content;
        return true;
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    return f.good();
}

} // namespace sps::report
