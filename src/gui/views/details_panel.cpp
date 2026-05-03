#include "details_panel.hpp"
#include "ui_details_panel.h"

#include <QtGlobal>   //Round()를 쓰기 위해 필요

namespace sps::gui {

DetailsPanel::DetailsPanel(QWidget* parent)
    //부모 생성자 호출하여 QWidget 초기화, 그리고 ui_ 포인터를 new Ui::DetailsPanel로 초기화
    : QWidget(parent), ui_(new Ui::DetailsPanel)
{
    ui_->setupUi(this); //.ui에 정의된 레이아웃과 위젯들을 현재 DetailsPanel 위젯에 생성/배치.
}

DetailsPanel::~DetailsPanel() { delete ui_; } //생성자에서 new Ui::DetailsPanel로 만들었으니 삭제.

//선택된 스캔 결과 하나를 받아서 상세 HTML 생성
void DetailsPanel::showResult(const core::ScanResult& r) {
    QString html;

    //호스트, 포트, 프로토콜, 서비스 이름을 제목으로 표시
    //<h3>example.com:443/tcp — https</h3> <- 이런 형태가됨.
    html += QString("<h3>%1:%2/%3 &mdash; %4</h3>")
        .arg(QString::fromStdString(r.target_host))
        .arg(r.port)
        .arg(QString::fromStdString(r.protocol))
        .arg(QString::fromStdString(r.service.name));

    //제품명과 버전을 표시
    html += QString("<b>Product:</b> %1 %2<br>")
        .arg(QString::fromStdString(r.service.product))
        .arg(QString::fromStdString(r.service.version));
    //추가 정보가 있으면 표시
    if (!r.service.extra_info.empty())
        html += QString("<b>Info:</b> %1<br>")
            .arg(QString::fromStdString(r.service.extra_info));

    //RTT와 Risk Score를 표시
    html += QString("<b>RTT:</b> %1 ms<br>")
        .arg(r.rtt.count());
    html += QString("<b>Risk Score:</b> %1<br><br>")
        .arg(r.max_risk(), 0, 'f', 2);

    // Banner. 서비스 배너가 있으면 pre 블록으로 보여줌.
    if (!r.service.banner_raw.empty()) {
        html += "<b>Banner:</b><pre style='background:#1a1a1a; padding:8px;'>";
        html += QString::fromStdString(r.service.banner_raw)
                    .toHtmlEscaped() //배너 문자열에 <script> 같은 HTML이 들어 있어도 실제 HTML로 실행되지 않게 escape. 보안상 중요한 처리임.
                    .left(512); //너무 긴 배너를 512자로 자름. 실제로는 배너가 그렇게 길 일이 거의 없지만, 혹시 모를 UI 깨짐 방지용.
        html += "</pre><br>";  
    } 

    //OS/CDN/JA4 정보 중에 값이 있는 항목만 출력함. 예를 들어 OS 정보가 없으면 OS 항목 자체가 안 보이게 됨.
    if (!r.os_guess.empty())
        html += "<b>OS:</b> " + QString::fromStdString(r.os_guess).toHtmlEscaped() + "<br>";
    if (!r.cdn.empty())
        html += "<b>CDN/WAF:</b> " + QString::fromStdString(r.cdn).toHtmlEscaped() + "<br>";
    if (!r.ja4s.empty())
        html += "<b>JA4S:</b> <code>" + QString::fromStdString(r.ja4s).toHtmlEscaped() + "</code><br>";
    if (!r.ja4x.empty())
        html += "<b>JA4X:</b> <code>" + QString::fromStdString(r.ja4x).toHtmlEscaped() + "</code><br>";
    if (!r.os_guess.empty() || !r.cdn.empty() || !r.ja4s.empty() || !r.ja4x.empty())
        html += "<br>";

    // CVE list
    if (!r.cves.empty()) {
        html += "<h4>Vulnerabilities</h4>";
        for (const auto& cve : r.cves) {
          //각 CVE마다 색상을 계산
            QString color = cvss_html_color(cve.cvss_score);
            QString epssColor = epss_html_color(cve.epss);
            const double risk = static_cast<double>(cve.cvss_score) * cve.epss;
            html += QString(
                "<div style='margin-bottom:8px; padding:6px; "
                "background:%1; border-radius:4px;'>"
                "<b>%2</b> &mdash; CVSS: %3 | "
                "<span style='background:%4; color:#ffffff; font-weight:bold; "
                "padding:1px 5px; border-radius:3px;'>EPSS: %5&#37;</span> "
                "<span>Percentile: %6&#37;</span><br>"
                "<b>Risk Score:</b> %7<br>"
                "<b>Nuclei Verified:</b> %8<br>"
                "<small>%9</small></div>")
                .arg(color)
                .arg(QString::fromStdString(cve.cve_id))
                .arg(cve.cvss_score, 0, 'f', 1)
                .arg(epssColor)
                .arg(qRound(cve.epss * 100.0)) //0.85 같은 EPSS를 85 퍼센트로 전환.
                .arg(qRound(cve.percentile * 100.0))
                .arg(risk, 0, 'f', 2)
                .arg(cve.nuclei_verified ? "yes" : "no")
                .arg(QString::fromStdString(cve.description).toHtmlEscaped());
        }
    } else {
        html += "<i>No known CVEs</i>";
    }

    ui_->textDisplay->setHtml(html);
}

QString DetailsPanel::cvss_html_color(float score) {
    if (score >= 9.0f) return "#4a1010";
    if (score >= 7.0f) return "#4a2a08";
    if (score >= 4.0f) return "#3a3508";
    return "#2a2a2a";
}

//cve의 EPSS 점수에 따라 HTML 색상 반환하는 함수. EPSS 0.5 이상은 빨강, 0.1 이상은 노랑, 그 미만은 초록으로 표시.
QString DetailsPanel::epss_html_color(double epss) {
    if (epss >= 0.50) return "#b41e1e";
    if (epss >= 0.10) return "#b4aa1e";
    return "#287828";
}

} 
