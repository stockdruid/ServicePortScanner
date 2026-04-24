// Qt 테스트 공용 main — QCoreApplication 필요 (event loop 를 쓰는 QSignalSpy 등).
// Catch2WithMain 대신 본 파일이 main 역할.

#include <QCoreApplication>
#include <catch2/catch_session.hpp>

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    return Catch::Session().run(argc, argv);
}
