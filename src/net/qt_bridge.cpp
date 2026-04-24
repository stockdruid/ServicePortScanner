#include "qt_bridge.hpp"

#include <QMetaObject>
#include <Qt>

#include <utility>

namespace sps::net {

QtBridge::QtBridge(QObject* parent) : QObject(parent) {
    // QueuedConnection 이 ScanResult 를 스레드 간 전달하려면 메타타입 등록 필수.
    // 중복 호출해도 안전 (Qt 내부에서 중복 방지).
    qRegisterMetaType<sps::core::ScanResult>("sps::core::ScanResult");
}

void QtBridge::postResult(sps::core::ScanResult r) {
    QMetaObject::invokeMethod(
        this,
        [this, r = std::move(r)]() mutable { emit resultReady(r); },
        Qt::QueuedConnection);
}

void QtBridge::postProgress(int done, int total) {
    QMetaObject::invokeMethod(
        this,
        [this, done, total]() { emit progressChanged(done, total); },
        Qt::QueuedConnection);
}

void QtBridge::postFinished() {
    QMetaObject::invokeMethod(
        this,
        [this]() { emit scanFinished(); },
        Qt::QueuedConnection);
}

} // namespace sps::net
