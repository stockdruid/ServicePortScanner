#include "net/qt_bridge.hpp"

#include <QCoreApplication>
#include <QEventLoop>
#include <QSignalSpy>
#include <catch2/catch_test_macros.hpp>

#include <thread>

using sps::core::PortState;
using sps::core::ScanResult;

TEST_CASE("QtBridge: postResult from worker reaches main thread", "[qt_bridge]") {
    sps::net::QtBridge bridge;
    QSignalSpy spy(&bridge, &sps::net::QtBridge::resultReady);

    std::thread worker([&] {
        ScanResult r;
        r.host = "127.0.0.1";
        r.port = 22;
        r.state = PortState::Open;
        r.service = "ssh";
        bridge.postResult(r);
    });
    worker.join();

    // QSignalSpy::wait 는 내부적으로 processEvents 수행.
    REQUIRE(spy.wait(1000));
    REQUIRE(spy.count() == 1);

    const auto args = spy.takeFirst();
    const auto r = args.at(0).value<ScanResult>();
    REQUIRE(r.port == 22);
    REQUIRE(r.service == "ssh");
    REQUIRE(r.state == PortState::Open);
}

TEST_CASE("QtBridge: progress events preserve order", "[qt_bridge]") {
    sps::net::QtBridge bridge;
    QSignalSpy progSpy(&bridge, &sps::net::QtBridge::progressChanged);
    QSignalSpy finSpy (&bridge, &sps::net::QtBridge::scanFinished);

    std::thread worker([&] {
        for (int i = 1; i <= 5; ++i) bridge.postProgress(i, 5);
        bridge.postFinished();
    });
    worker.join();

    // 첫 신호 도착 대기.
    REQUIRE(progSpy.wait(1000));
    // 남은 이벤트 플러시.
    QCoreApplication::processEvents(QEventLoop::AllEvents, 200);

    REQUIRE(progSpy.count() == 5);
    REQUIRE(finSpy.count()  == 1);

    // 순서 검증.
    for (int i = 0; i < 5; ++i) {
        const auto a = progSpy.at(i);
        REQUIRE(a.at(0).toInt() == i + 1);
        REQUIRE(a.at(1).toInt() == 5);
    }
}

TEST_CASE("QtBridge: many posts from multiple workers", "[qt_bridge]") {
    sps::net::QtBridge bridge;
    QSignalSpy spy(&bridge, &sps::net::QtBridge::resultReady);

    constexpr int kWorkers = 4;
    constexpr int kPerWorker = 25;
    std::vector<std::thread> ts;
    ts.reserve(kWorkers);
    for (int w = 0; w < kWorkers; ++w) {
        ts.emplace_back([&bridge, w] {
            for (int i = 0; i < kPerWorker; ++i) {
                ScanResult r;
                r.host = "10.0.0.1";
                r.port = static_cast<std::uint16_t>(w * 1000 + i);
                bridge.postResult(r);
            }
        });
    }
    for (auto& t : ts) t.join();

    // 이벤트 큐 다 비울 때까지 processEvents.
    const int total = kWorkers * kPerWorker;
    while (spy.count() < total) {
        if (!spy.wait(200)) break;
    }
    REQUIRE(spy.count() == total);
}
