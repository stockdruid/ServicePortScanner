#include "html_writer.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace sps::report {

namespace {

const char* state_str(core::PortState s) {
    switch (s) {
        case core::PortState::Open:     return "open";
        case core::PortState::Closed:   return "closed";
        case core::PortState::Filtered: return "filtered";
        default:                        return "unknown";
    }
}

const char* severity_str(core::Severity s) {
    switch (s) {
        case core::Severity::Critical: return "critical";
        case core::Severity::High:     return "high";
        case core::Severity::Medium:   return "medium";
        case core::Severity::Low:      return "low";
        default:                       return "none";
    }
}

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;
        }
    }
    return out;
}

std::string cvss_style(float cvss) {
    if (cvss >= 9.0f) return "background:#b41e1e;color:#fff;font-weight:700;";
    if (cvss >= 7.0f) return "background:#c87814;color:#fff;font-weight:700;";
    if (cvss >= 4.0f) return "background:#b4aa1e;color:#fff;font-weight:700;";
    return "background:#505050;color:#fff;font-weight:700;";
}

std::string epss_style(double epss) {
    if (epss >= 0.50) return "background:#b41e1e;color:#fff;font-weight:700;";
    if (epss >= 0.10) return "background:#b4aa1e;color:#fff;font-weight:700;";
    return "background:#287828;color:#fff;font-weight:700;";
}

} // namespace

void HtmlWriter::write(const std::string& path,
                       const std::vector<core::ScanResult>& results) {
    int open = 0;
    int closed = 0;
    int filtered = 0;
    size_t total_cves = 0;

    for (const auto& r : results) {
        if (r.state == core::PortState::Open) ++open;
        else if (r.state == core::PortState::Closed) ++closed;
        else if (r.state == core::PortState::Filtered) ++filtered;
        total_cves += r.cves.size();
    }

    std::ostringstream ss;
    ss << "<!DOCTYPE html>\n<html><head><meta charset='UTF-8'>\n"
       << "<title>SPS Scan Report</title>\n"
       << "<style>"
       << "body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#ddd;padding:24px;}"
       << "h1,h2{color:#fff;}h1{border-bottom:2px solid #3a6ea5;padding-bottom:10px;}"
       << ".summary{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0 24px;}"
       << ".metric{background:#2a2a2a;border:1px solid #444;padding:10px 14px;border-radius:4px;}"
       << "table{border-collapse:collapse;width:100%;margin:16px 0 28px;}"
       << "th,td{border:1px solid #444;padding:8px;text-align:left;vertical-align:top;}"
       << "th{background:#333;color:#fff;}tr:nth-child(even){background:#282828;}"
       << ".detail{background:#252525;border:1px solid #3d3d3d;border-radius:4px;padding:12px;margin:12px 0;}"
       << "pre{background:#151515;border:1px solid #333;padding:8px;white-space:pre-wrap;overflow:auto;}"
       << ".cve{margin:6px 0;padding:6px;background:#303030;border-radius:4px;}"
       << "code{color:#b8d7ff;}"
       << "</style></head><body>\n"
       << "<h1>Service Port Scanner Report</h1>\n"
       << "<div class='summary'>"
       << "<div class='metric'><b>Total Ports</b><br>" << results.size() << "</div>"
       << "<div class='metric'><b>Open</b><br>" << open << "</div>"
       << "<div class='metric'><b>Closed</b><br>" << closed << "</div>"
       << "<div class='metric'><b>Filtered</b><br>" << filtered << "</div>"
       << "<div class='metric'><b>Total CVEs</b><br>" << total_cves << "</div>"
       << "</div>\n"
       << "<h2>Results</h2>\n"
       << "<table><tr>"
       << "<th>Port</th><th>Proto</th><th>State</th><th>Service</th>"
       << "<th>Product</th><th>Version</th><th>CVSS</th><th>EPSS</th><th>Risk Score</th>"
       << "</tr>\n";

    for (const auto& r : results) {
        const float cvss = r.max_cvss();
        const double epss = r.max_epss();
        const double risk = static_cast<double>(cvss) * epss;
        ss << "<tr>"
           << "<td>" << r.port << "</td>"
           << "<td>" << html_escape(r.protocol) << "</td>"
           << "<td>" << state_str(r.state) << "</td>"
           << "<td>" << html_escape(r.service.name) << "</td>"
           << "<td>" << html_escape(r.service.product) << "</td>"
           << "<td>" << html_escape(r.service.version) << "</td>"
           << "<td style='" << cvss_style(cvss) << "'>" << cvss << "</td>"
           << "<td style='" << epss_style(epss) << "'>" << static_cast<int>(epss * 100) << "%</td>"
           << "<td>" << risk << "</td>"
           << "</tr>\n";
    }
    ss << "</table>\n";

    ss << "<h2>Result Details</h2>\n";
    for (const auto& r : results) {
        ss << "<div class='detail'>"
           << "<h3>" << html_escape(r.target_host) << ":" << r.port << "/"
           << html_escape(r.protocol) << " - "
           << html_escape(r.service.name) << "</h3>"
           << "<p><b>Resolved IP:</b> " << html_escape(r.resolved_ip) << "</p>"
           << "<p><b>State:</b> " << state_str(r.state) << "</p>"
           << "<p><b>RTT:</b> " << r.rtt.count() << " ms</p>"
           << "<p><b>Product:</b> " << html_escape(r.service.product) << " "
           << html_escape(r.service.version) << "</p>";
        if (!r.service.extra_info.empty()) ss << "<p><b>Info:</b> " << html_escape(r.service.extra_info) << "</p>";
        if (!r.os_guess.empty()) ss << "<p><b>OS:</b> " << html_escape(r.os_guess) << "</p>";
        if (!r.cdn.empty()) ss << "<p><b>CDN:</b> " << html_escape(r.cdn) << "</p>";
        if (!r.ja4s.empty()) ss << "<p><b>JA4S:</b> <code>" << html_escape(r.ja4s) << "</code></p>";
        if (!r.ja4x.empty()) ss << "<p><b>JA4X:</b> <code>" << html_escape(r.ja4x) << "</code></p>";
        if (!r.service.banner_raw.empty()) {
            ss << "<b>Banner:</b><pre>" << html_escape(r.service.banner_raw) << "</pre>";
        }
        if (!r.cves.empty()) {
            ss << "<b>CVEs:</b>";
            for (const auto& cve : r.cves) {
                const double risk = static_cast<double>(cve.cvss_score) * cve.epss;
                ss << "<div class='cve'><b>" << html_escape(cve.cve_id) << "</b> "
                   << "(" << severity_str(cve.severity) << ", CVSS " << cve.cvss_score
                   << ", EPSS " << static_cast<int>(cve.epss * 100)
                   << "%, Percentile " << static_cast<int>(cve.percentile * 100)
                   << "%, Risk " << risk
                   << ", Nuclei Verified " << (cve.nuclei_verified ? "yes" : "no") << ")<br>"
                   << html_escape(cve.description) << "</div>";
            }
        }
        ss << "</div>\n";
    }

    ss << "</body></html>\n";

    std::ofstream out(path);
    if (!out) throw std::runtime_error("failed to open HTML export path");
    out << ss.str();
}

} // namespace sps::report
