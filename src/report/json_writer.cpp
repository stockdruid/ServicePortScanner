#include "json_writer.hpp"

#include <fstream>
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

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) out += ' ';
                else out += c;
        }
    }
    return out;
}

} // namespace

void JsonWriter::write(const std::string& path,
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

    std::ofstream out(path);
    if (!out) throw std::runtime_error("failed to open JSON export path");

    out << "{\n"
        << "  \"scan_summary\": {\n"
        << "    \"total_ports\": " << results.size() << ",\n"
        << "    \"open\": " << open << ",\n"
        << "    \"closed\": " << closed << ",\n"
        << "    \"filtered\": " << filtered << ",\n"
        << "    \"total_cves\": " << total_cves << "\n"
        << "  },\n"
        << "  \"results\": [";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        out << "\n"
            << "    {\n"
            << "      \"target_host\": \"" << json_escape(r.target_host) << "\",\n"
            << "      \"resolved_ip\": \"" << json_escape(r.resolved_ip) << "\",\n"
            << "      \"port\": " << r.port << ",\n"
            << "      \"protocol\": \"" << json_escape(r.protocol) << "\",\n"
            << "      \"state\": \"" << state_str(r.state) << "\",\n"
            << "      \"service\": {\n"
            << "        \"name\": \"" << json_escape(r.service.name) << "\",\n"
            << "        \"product\": \"" << json_escape(r.service.product) << "\",\n"
            << "        \"version\": \"" << json_escape(r.service.version) << "\",\n"
            << "        \"extra_info\": \"" << json_escape(r.service.extra_info) << "\",\n"
            << "        \"banner_raw\": \"" << json_escape(r.service.banner_raw) << "\"\n"
            << "      },\n"
            << "      \"cves\": [";

        for (size_t j = 0; j < r.cves.size(); ++j) {
            const auto& cve = r.cves[j];
            out << "\n"
                << "        {\n"
                << "          \"cve_id\": \"" << json_escape(cve.cve_id) << "\",\n"
                << "          \"description\": \"" << json_escape(cve.description) << "\",\n"
                << "          \"cvss_score\": " << cve.cvss_score << ",\n"
                << "          \"severity\": \"" << severity_str(cve.severity) << "\",\n"
                << "          \"epss\": " << cve.epss << ",\n"
                << "          \"percentile\": " << cve.percentile << ",\n"
                << "          \"risk_score\": " << static_cast<double>(cve.cvss_score) * cve.epss << ",\n"
                << "          \"nuclei_verified\": " << (cve.nuclei_verified ? "true" : "false") << "\n"
                << "        }";
            if (j + 1 < r.cves.size()) out << ",";
        }

        out << "\n"
            << "      ],\n"
            << "      \"cve_count\": " << r.cves.size() << ",\n"
            << "      \"max_cvss\": " << r.max_cvss() << ",\n"
            << "      \"max_epss\": " << r.max_epss() << ",\n"
            << "      \"max_risk\": " << r.max_risk() << ",\n"
            << "      \"verified_cve_count\": " << r.verified_cve_count() << ",\n"
            << "      \"ja4s\": \"" << json_escape(r.ja4s) << "\",\n"
            << "      \"ja4x\": \"" << json_escape(r.ja4x) << "\",\n"
            << "      \"cdn\": \"" << json_escape(r.cdn) << "\",\n"
            << "      \"os_guess\": \"" << json_escape(r.os_guess) << "\",\n"
            << "      \"rtt_ms\": " << r.rtt.count() << "\n"
            << "    }";
        if (i + 1 < results.size()) out << ",";
    }

    out << "\n"
        << "  ]\n"
        << "}\n";
}

} // namespace sps::report
