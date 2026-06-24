#include "scope_warning_dialog.hpp"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace sps::gui {

ScopeWarningDialog::ScopeWarningDialog(const QString& target,
                                       const QString& reason,
                                       QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("외부 자산 스캔 경고"));
    setMinimumWidth(480);
    setModal(true);

    auto* icon_label = new QLabel(QStringLiteral("⚠"), this);
    icon_label->setStyleSheet(QStringLiteral(
        "font-size: 32px; color: #e8a000; padding-right: 8px;"));
    icon_label->setAlignment(Qt::AlignTop | Qt::AlignHCenter);

    auto* title_label = new QLabel(
        QStringLiteral("<b>외부 자산 스캔 경고</b>"), this);
    title_label->setStyleSheet(QStringLiteral("font-size: 14px;"));

    auto* desc_label = new QLabel(this);
    desc_label->setWordWrap(true);
    desc_label->setText(
        QStringLiteral(
            "<b>대상:</b> %1<br>"
            "<b>사유:</b> %2<br><br>"
            "입력한 주소는 RFC 1918 사설 대역(10.x, 172.16.x, 192.168.x) 또는 "
            "루프백 범위에 속하지 않습니다.<br>"
            "본인 소유가 아닌 자산을 무단으로 스캔하는 행위는 불법일 수 있습니다.")
            .arg(target, reason));

    auto* audit_notice = new QLabel(
        QStringLiteral("📋 스캔 기록은 <b>~/.spscan/audit.log</b> 에 저장됩니다."),
        this);
    audit_notice->setStyleSheet(
        QStringLiteral("color: #888; font-size: 11px; padding-top: 4px;"));

    consent_check_ = new QCheckBox(
        QStringLiteral("이 자산을 스캔할 명시적 권한이 있음을 확인합니다"), this);
    audit_check_ = new QCheckBox(
        QStringLiteral("스캔 결과가 audit log에 기록됨을 인지합니다"), this);

    auto* buttons = new QDialogButtonBox(this);
    proceed_btn_ = buttons->addButton(
        QStringLiteral("스캔 진행"), QDialogButtonBox::AcceptRole);
    auto* cancel_btn = buttons->addButton(
        QStringLiteral("취소"), QDialogButtonBox::RejectRole);
    proceed_btn_->setEnabled(false);
    proceed_btn_->setStyleSheet(
        QStringLiteral("QPushButton:enabled { color: #e8a000; font-weight: bold; }"));

    connect(proceed_btn_, &QPushButton::clicked, this, &QDialog::accept);
    connect(cancel_btn, &QPushButton::clicked, this, &QDialog::reject);
    connect(consent_check_, &QCheckBox::toggled,
            this, &ScopeWarningDialog::on_checkbox_toggled);
    connect(audit_check_, &QCheckBox::toggled,
            this, &ScopeWarningDialog::on_checkbox_toggled);

    auto* top_row = new QHBoxLayout;
    top_row->addWidget(icon_label, 0);
    auto* text_col = new QVBoxLayout;
    text_col->addWidget(title_label);
    text_col->addSpacing(6);
    text_col->addWidget(desc_label);
    text_col->addWidget(audit_notice);
    top_row->addLayout(text_col, 1);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(top_row);
    layout->addSpacing(12);
    layout->addWidget(consent_check_);
    layout->addWidget(audit_check_);
    layout->addSpacing(8);
    layout->addWidget(buttons);
}

void ScopeWarningDialog::on_checkbox_toggled() {
    proceed_btn_->setEnabled(
        consent_check_->isChecked() && audit_check_->isChecked());
}

} // namespace sps::gui
