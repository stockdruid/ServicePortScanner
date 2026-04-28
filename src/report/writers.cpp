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
        item["host"] = r.host;
        item["port"] = r.port;
        item["state"] = state_str(r.state);
        item["service"] = r.service;
        item["version"] = r.version;
        item["banner"] = r.banner;
        item["ja4"] = r.ja4;
        nlohmann::json cves = nlohmann::json::array();
        for (const auto& c : r.cves) {
            cves.push_back({{"id", c.id}, {"cvss", c.cvss}});
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
        double top_cvss = 0;
        for (const auto& c : r.cves) {
            if (c.cvss > top_cvss) { top_cvss = c.cvss; top_id = c.id; }
        }
        ss << escape_csv_field(r.host) << ','
           << r.port << ','
           << state_str(r.state) << ','
           << escape_csv_field(r.service) << ','
           << escape_csv_field(r.version) << ','
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
        double top_cvss = 0;
        for (const auto& c : r.cves) {
            if (c.cvss > top_cvss) { top_cvss = c.cvss; top_id = c.id; }
        }
        const char* row_class =
            (top_cvss >= 9.0) ? "crit" :
            (top_cvss >= 7.0) ? "high" :
            (top_cvss >= 4.0) ? "med"  : "";
        ss << "<tr class='" << row_class << "'>"
           << "<td>" << escape_html(r.host) << "</td>"
           << "<td>" << r.port << "</td>"
           << "<td>" << state_str(r.state) << "</td>"
           << "<td>" << escape_html(r.service) << "</td>"
           << "<td>" << escape_html(r.version) << "</td>"
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
