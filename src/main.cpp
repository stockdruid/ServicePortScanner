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
#include "fp/cve_lookup.hpp"
#include "fp/ja4.hpp"
#include "net/async_pool.hpp"
#include "net/rate_limiter.hpp"
#include "probes/probe.hpp"
#include "report/writers.hpp"

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
#include <vector>

namespace {

namespace asio = boost::asio;
using sps::core::PortState;
using sps::core::ScanRequest;
using sps::core::ScanResult;

// 한 포트 처리: rate-limit → connect → (optional) probe → CVE lookup.
asio::awaitable<ScanResult>
scan_one(asio::any_io_executor exec,
         std::string host,
         std::uint16_t port,
         std::chrono::milliseconds timeout,
         sps::net::RateLimiter& limiter,
         const std::vector<sps::probes::ProbePtr>* probes,
         const sps::fp::CveDb* cves) {
    co_await limiter.acquire();

    // step 1: connect.
    ScanRequest req{host, port, timeout};
    auto base = co_await sps::core::connect_scan(exec, req);
    if (base.state != PortState::Open || probes == nullptr) {
        co_return base;
    }

    // step 2: probe (재접속 — connect_scan 가 socket 을 닫았으므로).
    asio::ip::tcp::resolver resolver(exec);
    boost::system::error_code ec;
    auto results = co_await resolver.async_resolve(
        host, std::to_string(port),
        asio::redirect_error(asio::use_awaitable, ec));
    if (ec) co_return base;

    asio::ip::tcp::socket sock(exec);
    co_await asio::async_connect(sock, results,
                                  asio::redirect_error(asio::use_awaitable, ec));
    if (ec) co_return base;

    for (const auto& p : *probes) {
        const auto hints = p->hint_ports();
        const bool match_hint = hints.empty() ||
            std::find(hints.begin(), hints.end(), port) != hints.end();
        if (!match_hint) continue;

        auto out = co_await p->identify(sock, timeout);
        if (out.matched) {
            base.service = std::move(out.service);
            base.version = std::move(out.version);
            base.banner  = std::move(out.banner);
            if (base.service == "tls") {
                base.ja4 = sps::fp::compute_ja4(
                    {base.version, base.version, ""});
            }
            break;
        }
        // 다음 probe 를 위해 소켓 재구성.
        sock.close(ec);
        sock = asio::ip::tcp::socket(exec);
        co_await asio::async_connect(sock, results,
                                      asio::redirect_error(asio::use_awaitable, ec));
        if (ec) break;
    }
    sock.close(ec);

    if (cves && !cves->empty() && !base.service.empty() && !base.version.empty()) {
        base.cves = cves->lookup(base.service, base.version);
    }
    co_return base;
}

int run(const sps::cli::Args& args) {
    sps::fp::CveDb cves;
    if (!args.cve_db_path.empty()) {
        cves = sps::fp::CveDb::load(args.cve_db_path);
        fmt::print(stderr, "[spscan] CVE entries loaded: {}\n", cves.size());
    }
    auto probes = sps::probes::default_probes();

    sps::net::AsyncPool pool(args.threads);
    pool.start();
    sps::net::RateLimiter limiter(pool.executor(), args.rate, args.rate);

    std::vector<std::future<ScanResult>> futs;
    futs.reserve(args.ports.size());
    for (std::uint16_t p : args.ports) {
        auto fut = asio::co_spawn(
            pool.executor(),
            scan_one(pool.executor(), args.target, p, args.timeout,
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
            results.push_back(std::move(r));
        } catch (const std::exception& e) {
            fmt::print(stderr, "[spscan] task error: {}\n", e.what());
        }
    }
    pool.stop();

    fmt::print(stderr, "[spscan] open ports: {} / {}\n",
               open_count, results.size());

    if (args.report == sps::cli::ReportKind::None) {
        for (const auto& r : results) {
            if (r.state != PortState::Open) continue;
            fmt::print("{:>5}/tcp  open  {} {}\n",
                       r.port, r.service, r.version);
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
