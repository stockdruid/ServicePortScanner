#pragma once

// io_context 워커 스레드 → Qt UI 스레드 결과 전달.
//
// 사용 규칙:
//  - QtBridge 인스턴스는 반드시 UI(main) 스레드에서 생성·소유.
//  - 워커는 postResult/postProgress/postFinished 만 호출 — 내부적으로
//    QMetaObject::invokeMethod + Qt::QueuedConnection 으로 UI 스레드에
//    이벤트를 큐잉한 뒤 거기서 emit.
//  - 결과는 복사본으로 전달 (소유권 단순화, race 차단).

#include "core/result.hpp"

#include <QMetaType>
#include <QObject>

Q_DECLARE_METATYPE(sps::core::ScanResult)

namespace sps::net {

class QtBridge : public QObject {
    Q_OBJECT
public:
    explicit QtBridge(QObject* parent = nullptr);

    // 아래 3개는 thread-safe. 어느 스레드에서든 호출 가능.
    void postResult(sps::core::ScanResult r);
    void postProgress(int done, int total);
    void postFinished();

signals:
    void resultReady(const sps::core::ScanResult& r);
    void progressChanged(int done, int total);
    void scanFinished();
};

} // namespace sps::net
