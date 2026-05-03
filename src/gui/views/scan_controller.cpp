#include "scan_controller.hpp"

#include "core/scanner.hpp"
#include "net/async_pool.hpp"
#include "net/rate_limiter.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include <algorithm>
#include <chrono>
#include <future>
#include <utility>

namespace sps::gui {

namespace asio = boost::asio;
using sps::core::PortState;
using sps::core::ScanRequest;
using sps::core::ScanResult;

namespace {

// CLI main.cpp 의 scan_one 과 동일 로직. 추후 src/core/scan_pipeline 으로
// 추출 예정 (현재는 의도적 중복 — 통합 변동 최소화).
asio::awaitable<ScanResult>
scan_one(asio::any_io_executor exec,
         std::string host,
         std::uint16_t port,
         std::chrono::milliseconds timeout,
         sps::net::RateLimiter& limiter,
         const std::vector<sps::probes::ProbePtr>* probes,
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

    for (const auto& p : *probes) {
        const auto hints = p->hint_ports();
        const bool match_hint = hints.empty() ||
            std::find(hints.begin(), hints.end(), port) != hints.end();
        if (!match_hint) continue;

        auto out = co_await p->identify(sock, timeout);
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

} // namespace

ScanController::ScanController(QObject* parent)
    : QObject(parent), bridge_(new sps::net::QtBridge(this)) {
    // bridge_ 시그널 → controller 시그널 forward.
    connect(bridge_, &sps::net::QtBridge::resultReady,
            this,    &ScanController::resultReady);
    connect(bridge_, &sps::net::QtBridge::progressChanged,
            this,    &ScanController::progressChanged);
    connect(bridge_, &sps::net::QtBridge::scanFinished,
            this,    &ScanController::scanFinished);
}

ScanController::~ScanController() {
    cancel_.store(true);
    if (worker_.joinable()) worker_.join();
}

void ScanController::setProbes(std::vector<sps::probes::ProbePtr> p) {
    probes_ = std::move(p);
}
void ScanController::setCveDb(sps::fp::CveDb db) {
    cves_ = std::move(db);
}
void ScanController::setEpssDb(sps::fp::EpssDb db) {
    epss_ = std::move(db);
}
void ScanController::setCdnDb(sps::fp::CdnDatabase db) {
    cdn_ = std::move(db);
}
void ScanController::setRate(double pps) {
    if (pps > 0.0) rate_ = pps;
}
void ScanController::setTimeout(std::chrono::milliseconds t) {
    if (t.count() > 0) timeout_ = t;
}

void ScanController::startScan(const QString& target,
                                const QVector<quint16>& ports) {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        emit scanError(QStringLiteral("Scan already in progress"));
        return;
    }
    cancel_.store(false);

    // 이전 worker 가 .joinable() 이면 (이미 끝남) 정리 후 새로 시작.
    if (worker_.joinable()) worker_.join();

    std::string host = target.toStdString();
    std::vector<std::uint16_t> p;
    p.reserve(static_cast<std::size_t>(ports.size()));
    for (auto v : ports) p.push_back(v);

    worker_ = std::thread(
        [this, host = std::move(host), p = std::move(p)]() mutable {
            runScan(std::move(host), std::move(p));
            running_.store(false);
        });
}

void ScanController::cancelScan() {
    cancel_.store(true);
    // 진행 중인 future 들은 그대로 완료. 다음 future 처리에서 break.
}

void ScanController::runScan(std::string target,
                              std::vector<std::uint16_t> ports) {
    try {
        sps::net::AsyncPool pool(0);  // 0 = hardware_concurrency
        pool.start();

        const auto mode = sps::net::RateLimiter::Mode::Adaptive;
        sps::net::RateLimiter limiter(pool.executor(), rate_, rate_, mode,
                                       rate_ * 10.0);

        std::vector<std::future<ScanResult>> futs;
        futs.reserve(ports.size());
        for (auto port : ports) {
            if (cancel_.load()) break;
            auto fut = asio::co_spawn(
                pool.executor(),
                scan_one(pool.executor(), target, port,
                          timeout_,
                          limiter,
                          probes_.empty() ? nullptr : &probes_,
                          cves_.empty() ? nullptr : &cves_),
                asio::use_future);
            futs.push_back(std::move(fut));
        }

        const int total = static_cast<int>(futs.size());
        const std::string cdn_provider = cdn_.empty() ? std::string{} : cdn_.lookup(target);
        int done = 0;

        for (auto& f : futs) {
            if (cancel_.load()) break;
            try {
                auto r = f.get();
                r.cdn = cdn_provider;
                if (!epss_.empty()) {
                    for (auto& hit : r.cves) {
                        const auto e = epss_.lookup(hit.cve_id);
                        hit.epss = e.epss;
                        hit.percentile = e.percentile;
                    }
                }
                bridge_->postResult(std::move(r));
            } catch (const std::exception&) {
                // 단일 future 실패는 전체 스캔 중단 사유 아님 — 계속.
            }
            ++done;
            bridge_->postProgress(done, total);
        }

        pool.stop();
    } catch (const std::exception& e) {
        emit scanError(QString("Scan error: %1").arg(QString::fromUtf8(e.what())));
    }
    bridge_->postFinished();
}

} // namespace sps::gui
