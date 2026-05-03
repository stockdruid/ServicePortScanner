#include "settings_dialog.hpp"

#include <QApplication>
#include <QColor>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QPalette>
#include <QSettings>
#include <QSpinBox>
#include <QStyleFactory>
#include <QVBoxLayout>

namespace sps::gui {

namespace {

constexpr const char* kOrg            = "stockdruid";
constexpr const char* kApp            = "spscan";
constexpr const char* kKeyRate        = "scan/rate_pps";
constexpr const char* kKeyTimeout     = "scan/timeout_ms";
constexpr const char* kKeyTheme       = "ui/theme";

QPalette dark_palette() {
    QPalette p;
    p.setColor(QPalette::Window,          QColor(30, 30, 30));
    p.setColor(QPalette::WindowText,      QColor(220, 220, 220));
    p.setColor(QPalette::Base,            QColor(40, 40, 40));
    p.setColor(QPalette::AlternateBase,   QColor(50, 50, 50));
    p.setColor(QPalette::Text,            QColor(220, 220, 220));
    p.setColor(QPalette::Button,          QColor(50, 50, 50));
    p.setColor(QPalette::ButtonText,      QColor(220, 220, 220));
    p.setColor(QPalette::Highlight,       QColor(0, 120, 215));
    p.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
    p.setColor(QPalette::ToolTipBase,     QColor(50, 50, 50));
    p.setColor(QPalette::ToolTipText,     QColor(220, 220, 220));
    return p;
}

} // namespace

SettingsDialog::SettingsDialog(const Settings& current, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(QStringLiteral("Settings"));
    setMinimumWidth(380);

    rate_ = new QDoubleSpinBox(this);
    rate_->setRange(1.0, 10000.0);
    rate_->setDecimals(1);
    rate_->setSingleStep(10.0);
    rate_->setSuffix(QStringLiteral(" pps"));
    rate_->setValue(current.rate_pps);

    timeout_ = new QSpinBox(this);
    timeout_->setRange(100, 30000);
    timeout_->setSingleStep(100);
    timeout_->setSuffix(QStringLiteral(" ms"));
    timeout_->setValue(current.timeout_ms);

    theme_ = new QComboBox(this);
    theme_->addItem(QStringLiteral("Dark"));
    theme_->addItem(QStringLiteral("Light"));
    theme_->setCurrentIndex(current.theme == Theme::Dark ? 0 : 1);

    auto* form = new QFormLayout;
    form->addRow(QStringLiteral("Scan rate"), rate_);
    form->addRow(QStringLiteral("Per-port timeout"), timeout_);
    form->addRow(QStringLiteral("Theme"), theme_);

    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addSpacing(8);
    layout->addWidget(buttons);
}

Settings SettingsDialog::settings() const {
    Settings s;
    s.rate_pps   = rate_->value();
    s.timeout_ms = timeout_->value();
    s.theme      = theme_->currentIndex() == 0 ? Theme::Dark : Theme::Light;
    return s;
}

void apply_theme(QApplication& app, Theme t) {
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    if (t == Theme::Dark) {
        app.setPalette(dark_palette());
    } else {
        app.setPalette(QPalette());  // 시스템 기본
    }
}

Settings load_settings() {
    QSettings store(kOrg, kApp);
    Settings out;
    out.rate_pps   = store.value(kKeyRate,    100.0).toDouble();
    out.timeout_ms = store.value(kKeyTimeout, 1000).toInt();
    const auto theme_str = store.value(kKeyTheme, QStringLiteral("dark"))
                                .toString().toLower();
    out.theme = (theme_str == QStringLiteral("light"))
                  ? Theme::Light : Theme::Dark;
    return out;
}

void save_settings(const Settings& s) {
    QSettings store(kOrg, kApp);
    store.setValue(kKeyRate,    s.rate_pps);
    store.setValue(kKeyTimeout, s.timeout_ms);
    store.setValue(kKeyTheme,
                   s.theme == Theme::Dark ? QStringLiteral("dark")
                                          : QStringLiteral("light"));
}

} // namespace sps::gui
