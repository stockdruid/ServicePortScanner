#pragma once

// SettingsDialog — 스캔 속도(pps), 포트 타임아웃(ms), GUI 테마(다크/라이트).
// QSettings("stockdruid", "spscan") 으로 디스크에 영구 저장.

#include <QDialog>

class QApplication;
class QComboBox;
class QDoubleSpinBox;
class QSpinBox;

namespace sps::gui {

enum class Theme { Dark, Light };

struct Settings {
    double rate_pps  = 100.0;
    int    timeout_ms = 1000;
    Theme  theme     = Theme::Dark;
};

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(const Settings& current, QWidget* parent = nullptr);
    [[nodiscard]] Settings settings() const;

private:
    QDoubleSpinBox* rate_    = nullptr;
    QSpinBox*       timeout_ = nullptr;
    QComboBox*      theme_   = nullptr;
};

// QApplication 팔레트 + style 적용. 차트(QtCharts)는 자체 테마 유지.
void apply_theme(QApplication& app, Theme t);

// QSettings 에서 로드 / 저장.
[[nodiscard]] Settings load_settings();
void save_settings(const Settings& s);

} // namespace sps::gui
