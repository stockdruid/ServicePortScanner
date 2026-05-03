#pragma once

// ScanController — 백엔드(AsyncPool + RateLimiter + scan_one) 와
// GUI views 사이의 어댑터.
//
// 사용 규칙:
//  - UI 스레드에서 생성·소유. 내부 QtBridge 가 모든 cross-thread 신호를
//    Qt::QueuedConnection 으로 UI 스레드에 안전하게 큐잉.
//  - startScan() 은 worker std::thread 를 띄워 io_context 를 백그라운드 실행.
//  - cancelScan() 은 cancel flag 만 set — 진행 중인 future 는 그대로 완료
//    되지만 다음 future 처리에서 break 후 io_context 종료.
//  - 다음 startScan 호출 전에 이전 worker 가 끝났을 수 있으므로, 진행
//    상태는 running_ atomic 으로 따로 추적.

#include <QObject>
#include <QString>
#include <QVector>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include "core/result.hpp"
#include "fp/cdn_lookup.hpp"
#include "fp/cve_lookup.hpp"
#include "fp/epss_lookup.hpp"
#include "net/qt_bridge.hpp"
#include "probes/probe_variant.hpp"

namespace sps::gui {

class ScanController : public QObject {
    Q_OBJECT
public:
    explicit ScanController(QObject* parent = nullptr);
    ~ScanController() override;

    ScanController(const ScanController&)            = delete;
    ScanController& operator=(const ScanController&) = delete;

    // 옵션 — startScan 호출 전에 설정. probe/CVE DB 가 비면 connect-only 스캔.
    void setProbes(std::vector<sps::probes::ProbeVariant> p);
    void setCveDb(sps::fp::CveDb db);
    void setEpssDb(sps::fp::EpssDb db);
    void setCdnDb(sps::fp::CdnDatabase db);
    void setRate(double pps);                         // default 100 pps
    void setTimeout(std::chrono::milliseconds t);     // default 1000 ms

    bool isScanning() const noexcept { return running_.load(); }

public slots:
    void startScan(const QString& target,
                   const QVector<quint16>& ports);
    void cancelScan();

signals:
    void resultReady(const sps::core::ScanResult& r);
    void progressChanged(int done, int total);
    void scanFinished();
    void scanError(const QString& msg);

private:
    void runScan(std::string target,
                 std::vector<std::uint16_t> ports);

    sps::net::QtBridge*  bridge_ = nullptr;   // Qt parent 소유
    std::vector<sps::probes::ProbeVariant> probes_;
    sps::fp::CveDb       cves_;
    sps::fp::EpssDb      epss_;
    sps::fp::CdnDatabase cdn_;
    double               rate_     = 100.0;
    std::chrono::milliseconds timeout_{1000};

    std::atomic<bool>    running_{false};
    std::atomic<bool>    cancel_{false};
    std::thread          worker_;
};

} // namespace sps::gui
