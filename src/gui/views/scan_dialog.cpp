#include "scan_dialog.hpp"
#include "scope_warning_dialog.hpp"

#include "cli/args.hpp"
#include "cli/scope_guard.hpp"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

#include <string>

namespace sps::gui {

ScanDialog::ScanDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(QStringLiteral("New Scan"));
    setMinimumWidth(440);

    target_ = new QLineEdit(this);
    target_->setText(QStringLiteral("127.0.0.1"));
    target_->setPlaceholderText(
        QStringLiteral("IP address (e.g., 192.168.1.10) or RFC1918 host"));

    ports_ = new QLineEdit(this);
    ports_->setText(QStringLiteral("22,80,443,8080,8443"));
    ports_->setPlaceholderText(
        QStringLiteral("Examples: 22,80,443  or  1-1024  or  22,80-90,443"));

    allow_external_ = new QCheckBox(
        QStringLiteral("Allow external (non-RFC1918) target — I have authorization"),
        this);
    allow_external_->setChecked(false);

    auto* form = new QFormLayout;
    form->addRow(QStringLiteral("Target"), target_);
    form->addRow(QStringLiteral("Ports"), ports_);
    form->addRow(QStringLiteral(""), allow_external_);

    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Scan"));
    buttons->button(QDialogButtonBox::Ok)->setDefault(true);
    connect(buttons, &QDialogButtonBox::accepted, this, &ScanDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addSpacing(8);
    layout->addWidget(buttons);
}

void ScanDialog::accept() {
    const auto target = target_->text().trimmed();
    if (target.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Invalid input"),
            QStringLiteral("Target is required."));
        return;
    }

    const auto ports_str = ports_->text().trimmed();
    const auto port_vec = sps::cli::expand_port_spec(ports_str.toStdString());
    if (port_vec.empty()) {
        QMessageBox::warning(this, QStringLiteral("Invalid input"),
            QStringLiteral("Could not parse ports.\n"
                           "Examples: 22,80,443 / 1-1024 / 22,80-90,443"));
        return;
    }

    const sps::cli::ScopeOptions opts{ false };
    const auto decision = sps::cli::check_scope(target.toStdString(), opts);
    if (decision != sps::cli::ScopeDecision::Allowed) {
        const auto desc_sv = sps::cli::describe(decision);
        ScopeWarningDialog warn(target,
            QString::fromUtf8(desc_sv.data(),
                              static_cast<int>(desc_sv.size())),
            this);
        if (warn.exec() != QDialog::Accepted) return;
        allow_external_->setChecked(true);
    }

    QDialog::accept();
}

ScanRequest ScanDialog::request() const {
    ScanRequest r;
    r.target = target_->text().trimmed();

    const auto ports = sps::cli::expand_port_spec(
        ports_->text().trimmed().toStdString());
    r.ports.reserve(static_cast<int>(ports.size()));
    for (auto p : ports) r.ports.push_back(p);

    r.external_consent = allow_external_->isChecked();
    return r;
}

} // namespace sps::gui
