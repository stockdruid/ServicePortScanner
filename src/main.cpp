/*

spscan — CLI entry point (MVP, GUI 제외).

⠀⠀⠀⠀⢀⠴⣲⣯⣉⣽⣿⡛⠻⣶⠖⢒⢶⣦⣄⠀⠀⠀⠀⠀
⠀⠀⢀⡴⢁⡜⠉⠋⠉⠹⠉⠱⡄⠙⢦⣼⣾⣿⣿⣧⠀⠀⠀⠀
⠀⢀⡞⢀⡞⢀⡄⠀⠀⢀⢸⠀⠹⡀⠈⣟⠿⣿⣿⣟⣉⡇⠀⠀
⣴⣫⠀⢸⢠⣾⡇⢠⠀⢸⢰⢆⠀⡇⠀⢹⣿⣿⣿⣿⣌⡇⠀⠀
⠀⠀⢀⡼⢻⠛⢿⡾⠦⣿⣿⣿⣷⡇⠀⢸⠁⣯⣿⠛⡹⠛⣦⠀
⠀⢰⢨⠀⠈⢓⢺⢁⣀⠀⢿⢀⣼⠃⠀⣸⣠⠃⣇⡴⠁⠀⢸⡇
⠀⠘⣎⢓⢤⣄⣀⣉⡉⣁⣀⣠⣿⡆⢠⠟⠁⠀⠘⠁⠀⠀⢸⡇
⠀⠀⠈⢺⡿⠇⡀⠉⠉⠉⠉⢉⣼⡡⠋⠀⠀⢀⣴⠀⠀⣠⠟⠀
⠀⠀⠀⠀⢷⡀⢻⡶⣤⣤⠀⠀⠀⠀⣀⣤⡴⠛⡇⠀⠀⡏⠀⠀
⠀⠀⠀⠀⠈⠳⠼⠃⠀⠈⢧⡀⠀⠀⡇⠀⠀⠀⠻⣄⣀⡟⠀⠀도와줘... 도로롱...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠶⠾⠁⠀⠀⠀⠀⠈⠉⠀⠀
*/

#include "cli/args.hpp"
#include "cli/scope_guard.hpp"
#include "core/result.hpp"
#include "core/scanner.hpp"
#include "fp/cdn_lookup.hpp"
#include "fp/cve_lookup.hpp"
#include "fp/epss_lookup.hpp"
#include "net/async_pool.hpp"
#include "net/rate_limiter.hpp"
#include "probes/probe_variant.hpp"
#include "report/writers.hpp"
#include "scan/scan_pipeline.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include <fmt/core.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

namespace {

namespace asio = boost::asio;
using sps::core::PortState;
using sps::core::ScanRequest;
using sps::core::ScanResult;

// scan_one 은 src/scan/scan_pipeline.{hpp,cpp} 의 sps::scan::scan_one 사용.

int run(const sps::cli::Args& args) {
    sps::fp::CveDb cves;
    if (!args.cve_db_path.empty()) {
        cves = sps::fp::CveDb::load(args.cve_db_path);
        fmt::print(stderr, "[spscan] CVE entries loaded: {}\n", cves.size());
    }
    auto probes = sps::probes::default_probes(args.probes_db_path);

    auto cdn_db = args.cdn_db_path.empty()
        ? sps::fp::CdnDatabase::load_default()
        : sps::fp::CdnDatabase::load_from_file(args.cdn_db_path);
    if (cdn_db.empty() && !args.cdn_db_path.empty()) {
        cdn_db = sps::fp::CdnDatabase::load_default();
    }
    const std::string cdn_provider = cdn_db.lookup(args.target);
    if (!cdn_provider.empty()) {
        fmt::print(stderr, "[spscan] target {} → CDN/WAF: {}\n",
                   args.target, cdn_provider);
    }

    sps::fp::EpssDb epss;
    if (!args.epss_db_path.empty()) {
        epss = sps::fp::EpssDb::load(args.epss_db_path);
        fmt::print(stderr, "[spscan] EPSS entries loaded: {}\n", epss.size());
    }

    sps::net::AsyncPool pool(args.threads);
    pool.start();
    const auto mode = args.adaptive
        ? sps::net::RateLimiter::Mode::Adaptive
        : sps::net::RateLimiter::Mode::Fixed;
    sps::net::RateLimiter limiter(pool.executor(), args.rate, args.rate,
                                   mode, args.max_rate);
    fmt::print(stderr, "[spscan] rate mode: {} (start={:.1f} pps, cap={:.1f})\n",
               args.adaptive ? "adaptive" : "fixed",
               args.rate, args.max_rate);

    std::vector<std::future<ScanResult>> futs;
    futs.reserve(args.ports.size());
    for (std::uint16_t p : args.ports) {
        auto fut = asio::co_spawn(
            pool.executor(),
            sps::scan::scan_one(pool.executor(), args.target, p, args.timeout,
                                 limiter,
                                 args.no_probe ? nullptr : &probes,
                                 args.cve_db_path.empty() ? nullptr : &cves),
            asio::use_future);
        futs.push_back(std::move(fut));
    }

    std::vector<ScanResult> results;
    results.reserve(futs.size());
    int open_count = 0;
    for (auto& f : futs) {
        try {
            auto r = f.get();
            if (r.state == PortState::Open) ++open_count;
            r.cdn = cdn_provider;
            if (!epss.empty()) {
                for (auto& hit : r.cves) {
                    const auto e = epss.lookup(hit.cve_id);
                    hit.epss = e.epss;
                    hit.percentile = e.percentile;
                }
            }
            results.push_back(std::move(r));
        } catch (const std::exception& e) {
            fmt::print(stderr, "[spscan] task error: {}\n", e.what());
        }
    }
    pool.stop();

    fmt::print(stderr, "[spscan] open ports: {} / {}\n",
               open_count, results.size());
    if (args.adaptive) {
        fmt::print(stderr,
                   "[spscan] adaptive: rate={:.1f} pps, srtt={:.1f} ms, "
                   "loss={:.2f}% (n={})\n",
                   limiter.rate(), limiter.srtt_ms(),
                   limiter.loss_ratio() * 100.0, limiter.samples());
    }

    if (args.report == sps::cli::ReportKind::None) {
        for (const auto& r : results) {
            if (r.state != PortState::Open) continue;
            fmt::print("{:>5}/tcp  open  {} {}\n",
                       r.port, r.service.name, r.service.version);
        }
        return 0;
    }

    std::string body;
    switch (args.report) {
        case sps::cli::ReportKind::Json: body = sps::report::to_json(results); break;
        case sps::cli::ReportKind::Csv:  body = sps::report::to_csv(results);  break;
        case sps::cli::ReportKind::Html: body = sps::report::to_html(results); break;
        default: break;
    }
    if (!sps::report::write_to_file(args.out_path, body)) {
        fmt::print(stderr, "[spscan] failed to write: {}\n", args.out_path);
        return 2;
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    auto parsed = sps::cli::parse(argc, argv);
    if (!parsed.ok) {
        if (parsed.exit_code != 0) return parsed.exit_code;
        std::cerr << parsed.error << "\n";
        return 2;
    }

    auto decision = sps::cli::check_scope(
        parsed.args.target, {parsed.args.consent});
    if (decision != sps::cli::ScopeDecision::Allowed) {
        std::cerr << "[spscan] scope denied: "
                  << sps::cli::describe(decision) << "\n";
        return 3;
    }

    return run(parsed.args);
}
