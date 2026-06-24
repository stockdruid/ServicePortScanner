#pragma once

#include <QDialog>
#include <QString>

class QCheckBox;
class QPushButton;

namespace sps::gui {

class ScopeWarningDialog : public QDialog {
    Q_OBJECT
public:
    explicit ScopeWarningDialog(const QString& target,
                                const QString& reason,
                                QWidget* parent = nullptr);

private slots:
    void on_checkbox_toggled();

private:
    QCheckBox* consent_check_ = nullptr;
    QCheckBox* audit_check_ = nullptr;
    QPushButton* proceed_btn_ = nullptr;
};

} // namespace sps::gui
