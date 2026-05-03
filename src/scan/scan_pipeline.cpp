#include "scan/scan_pipeline.hpp"

#include "core/scanner.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <utility>
#include <variant>

namespace sps::scan {

namespace asio = boost::asio;
using sps::core::PortState;
using sps::core::ScanRequest;
using sps::core::ScanResult;

asio::awaitable<ScanResult>
scan_one(asio::any_io_executor exec,
         std::string host,
         std::uint16_t port,
         std::chrono::milliseconds timeout,
         sps::net::RateLimiter& limiter,
         const std::vector<sps::probes::ProbeVariant>* probes,
         const sps::fp::CveDb* cves) {
    co_await limiter.acquire();

    ScanRequest req{host, port, timeout};
    const auto t0 = std::chrono::steady_clock::now();
    auto base = co_await sps::core::connect_scan(exec, req);
    const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    base.rtt = rtt;
    const bool was_loss = (base.state == PortState::Filtered);
    limiter.on_response(rtt, was_loss);

    if (base.state != PortState::Open || probes == nullptr) {
        co_return base;
    }

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

    for (auto& probe : *probes) {
        const auto hints = std::visit(
            [](const auto& p) { return p.hint_ports(); }, probe);
        const bool match_hint = hints.empty() ||
            std::find(hints.begin(), hints.end(), port) != hints.end();
        if (!match_hint) continue;

        auto out = co_await std::visit(
            [&sock, timeout](auto& p) -> asio::awaitable<sps::probes::ProbeOutcome> {
                return p.identify(sock, timeout);
            }, probe);
        if (out.matched) {
            base.service.name       = std::move(out.service);
            base.service.version    = std::move(out.version);
            base.service.banner_raw = std::move(out.banner);
            base.ja4s = std::move(out.ja4s);
            base.ja4x = std::move(out.ja4x);
            break;
        }
        sock.close(ec);
        sock = asio::ip::tcp::socket(exec);
        co_await asio::async_connect(sock, results,
                                      asio::redirect_error(asio::use_awaitable, ec));
        if (ec) break;
    }
    sock.close(ec);

    if (cves && !cves->empty() && !base.service.name.empty() &&
        !base.service.version.empty()) {
        base.cves = cves->lookup(base.service.name, base.service.version);
    }
    co_return base;
}

} // namespace sps::scan
