#pragma once

// ScanDialog — 임의 target / ports 입력 + scope guard 체크.
//
// target: IP 또는 hostname (e.g., 127.0.0.1, 192.168.1.10, scanme.nmap.org).
// ports: nmap 스타일 spec — "22,80,443" / "1-1024" / "22,80-90,443" 등.
// allow_external: RFC1918+loopback 외부 IP 는 이 체크박스 켜야 진행.
//
// accept() 오버라이드 — OK 누르면 입력 검증 + scope 체크 후 통과 시에만 dialog
// 종료. 실패는 QMessageBox 로 즉시 피드백.

#include <QDialog>
#include <QString>
#include <QVector>

class QCheckBox;
class QLineEdit;

namespace sps::gui {

struct ScanRequest {
    QString          target;
    QVector<quint16> ports;
    bool             external_consent = false;
};

class ScanDialog : public QDialog {
    Q_OBJECT
public:
    explicit ScanDialog(QWidget* parent = nullptr);
    [[nodiscard]] ScanRequest request() const;

public slots:
    void accept() override;   // 입력 검증 + scope 체크 후 통과 시만 close.

private:
    QLineEdit* target_         = nullptr;
    QLineEdit* ports_          = nullptr;
    QCheckBox* allow_external_ = nullptr;
};

} // namespace sps::gui
