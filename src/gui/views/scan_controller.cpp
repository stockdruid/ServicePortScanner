#include "scan_controller.hpp"

#include "net/async_pool.hpp"
#include "net/rate_limiter.hpp"
#include "scan/scan_pipeline.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>

#include <chrono>
#include <future>
#include <utility>

namespace sps::gui {

namespace asio = boost::asio;
using sps::core::PortState;
using sps::core::ScanResult;

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

void ScanController::setProbes(std::vector<sps::probes::ProbeVariant> p) {
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
                sps::scan::scan_one(pool.executor(), target, port,
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
