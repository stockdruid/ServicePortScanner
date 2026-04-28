#include "cli/args.hpp"
#include "cli/top_ports.hpp"

#include <CLI/CLI.hpp>

#include <algorithm>
#include <charconv>
#include <set>
#include <sstream>

namespace sps::cli {

namespace {

bool parse_uint16(std::string_view s, std::uint16_t& out) {
    int v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size()) return false;
    if (v < 1 || v > 65535) return false;
    out = static_cast<std::uint16_t>(v);
    return true;
}

ReportKind parse_report(const std::string& s) {
    if (s == "json") return ReportKind::Json;
    if (s == "csv")  return ReportKind::Csv;
    if (s == "html") return ReportKind::Html;
    return ReportKind::None;
}

} // namespace

std::vector<std::uint16_t> expand_port_spec(std::string_view spec) {
    std::set<std::uint16_t> set;
    std::string token;
    auto flush = [&](std::string_view tok) -> bool {
        if (tok.empty()) return true;
        const auto dash = tok.find('-');
        if (dash == std::string_view::npos) {
            std::uint16_t p = 0;
            if (!parse_uint16(tok, p)) return false;
            set.insert(p);
            return true;
        }
        std::uint16_t lo = 0, hi = 0;
        if (!parse_uint16(tok.substr(0, dash), lo)) return false;
        if (!parse_uint16(tok.substr(dash + 1), hi)) return false;
        if (lo > hi) std::swap(lo, hi);
        for (std::uint32_t p = lo; p <= hi; ++p) {
            set.insert(static_cast<std::uint16_t>(p));
        }
        return true;
    };

    std::size_t start = 0;
    for (std::size_t i = 0; i <= spec.size(); ++i) {
        if (i == spec.size() || spec[i] == ',') {
            const auto piece = spec.substr(start, i - start);
            if (!flush(piece)) return {};
            start = i + 1;
        }
    }
    return std::vector<std::uint16_t>(set.begin(), set.end());
}

ParseResult parse(int argc, char** argv) {
    ParseResult res;
    CLI::App app{"spscan — service-aware port scanner (MVP CLI)"};

    std::string ports_spec = "1-1024";
    std::string report_str = "none";
    int timeout_ms = 2000;

    app.add_option("--target,-t", res.args.target, "Target IP (IPv4/IPv6)")
       ->required();
    app.add_option("--ports,-p", ports_spec,
                   "Port spec, e.g. 22,80,443 or 1-1024 or mix")
       ->capture_default_str();
    app.add_option("--rate", res.args.rate,
                   "Packets/sec rate limit (Adaptive 시 시작값)")
       ->capture_default_str()
       ->check(CLI::Range(1.0, 100000.0));
    app.add_option("--max-rate", res.args.max_rate,
                   "Adaptive 모드 상한 (loss<1% 일 때 여기까지 증속)")
       ->capture_default_str()
       ->check(CLI::Range(1.0, 100000.0));
    app.add_flag("--adaptive", res.args.adaptive,
                 "RTT/loss 기반 자동 송신율 조정 (RFC 6298 EWMA)");
    app.add_option("--top-ports", res.args.top_ports,
                   "상위 N 개 포트만 스캔 (--ports 무시)")
       ->check(CLI::Range(static_cast<std::size_t>(1),
                          static_cast<std::size_t>(1000)));
    app.add_option("--timeout-ms", timeout_ms, "Per-port I/O timeout")
       ->capture_default_str()
       ->check(CLI::Range(100, 60000));
    app.add_option("--report", report_str, "Report format: none|json|csv|html")
       ->capture_default_str()
       ->check(CLI::IsMember({"none", "json", "csv", "html"}));
    app.add_option("--out,-o", res.args.out_path, "Output file path");
    app.add_option("--cve-db", res.args.cve_db_path,
                   "Path to NVD-min JSON file");
    app.add_option("--threads,-j", res.args.threads,
                   "Worker threads (0 = auto)")
       ->capture_default_str();
    app.add_flag("--no-probe", res.args.no_probe,
                 "Skip protocol probes (connect-only)");
    app.add_flag("--i-know-what-im-doing", res.args.consent,
                 "Allow scanning external (non-RFC1918) IPs");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        res.exit_code = app.exit(e);
        std::ostringstream oss;
        oss << e.what();
        res.error = oss.str();
        res.ok = false;
        return res;
    }

    if (res.args.top_ports > 0) {
        res.args.ports = top_n_ports(res.args.top_ports);
    } else {
        res.args.ports = expand_port_spec(ports_spec);
    }
    if (res.args.ports.empty()) {
        res.error = "invalid port selection (--ports / --top-ports)";
        res.ok = false;
        return res;
    }
    if (res.args.max_rate < res.args.rate) {
        res.args.max_rate = res.args.rate;  // 정합성 보정
    }
    res.args.timeout = std::chrono::milliseconds(timeout_ms);
    res.args.report = parse_report(report_str);
    res.ok = true;
    return res;
}

} // namespace sps::cli
