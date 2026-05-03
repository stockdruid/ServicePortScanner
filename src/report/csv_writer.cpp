#include "csv_writer.hpp"

#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <string>

namespace sps::report {

namespace {

std::string csv_escape(const std::string& s) {
    bool needs_quotes = s.find_first_of(",\"\r\n") != std::string::npos;
    if (!needs_quotes) return s;

    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}

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

std::string bool_str(bool value) {
    return value ? "true" : "false";
}

std::string cve_list(const std::vector<core::CveInfo>& cves) {
    std::string out;
    for (size_t i = 0; i < cves.size(); ++i) {
        const auto& cve = cves[i];
        if (i > 0) out += "; ";
        out += cve.cve_id;
        out += "|severity=";
        out += severity_str(cve.severity);
        out += "|cvss=" + std::to_string(cve.cvss_score);
        out += "|epss=" + std::to_string(cve.epss);
        out += "|percentile=" + std::to_string(cve.percentile);
        out += "|risk=" + std::to_string(static_cast<double>(cve.cvss_score) * cve.epss);
        out += "|nuclei_verified=";
        out += bool_str(cve.nuclei_verified);
        out += "|description=";
        out += cve.description;
    }
    return out;
}

} // namespace

void CsvWriter::write(const std::string& path,
                      const std::vector<core::ScanResult>& results) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("failed to open CSV export path");
    out << std::fixed << std::setprecision(2);
    out << "Target_Host,Resolved_IP,Port,Protocol,State,Service,Product,Version,Extra_Info,Banner_Raw,"
        << "CVE_Count,Max_CVSS,Max_EPSS,Max_Risk,Verified_CVE_Count,JA4S,JA4X,CDN,OS,RTT_ms,CVEs\n";

    for (const auto& r : results) {
        out << csv_escape(r.target_host) << ","
            << csv_escape(r.resolved_ip) << ","
            << r.port << ","
            << csv_escape(r.protocol) << ","
            << state_str(r.state) << ","
            << csv_escape(r.service.name) << ","
            << csv_escape(r.service.product) << ","
            << csv_escape(r.service.version) << ","
            << csv_escape(r.service.extra_info) << ","
            << csv_escape(r.service.banner_raw) << ","
            << r.cves.size() << ","
            << r.max_cvss() << ","
            << r.max_epss() << ","
            << r.max_risk() << ","
            << r.verified_cve_count() << ","
            << csv_escape(r.ja4s) << ","
            << csv_escape(r.ja4x) << ","
            << csv_escape(r.cdn) << ","
            << csv_escape(r.os_guess) << ","
            << r.rtt.count() << ","
            << csv_escape(cve_list(r.cves)) << "\n";
    }
}

} // namespace sps::report
