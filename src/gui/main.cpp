#include <QApplication>

#include "gui/views/main_window.hpp"
#include "gui/views/settings_dialog.hpp"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("stockdruid"));
    QCoreApplication::setApplicationName(QStringLiteral("spscan"));

    // 저장된 설정 로드 후 테마 적용. MainWindow 가 같은 설정을 다시 로드해서
    // 컨트롤러에 rate/timeout 적용.
    const auto initial = sps::gui::load_settings();
    sps::gui::apply_theme(app, initial.theme);

    sps::gui::MainWindow w;
    w.setWindowTitle(QStringLiteral("Service Port Scanner"));
    w.resize(1200, 700);
    w.show();

    return app.exec();
}
