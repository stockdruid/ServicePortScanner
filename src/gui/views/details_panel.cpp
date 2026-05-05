#include "details_panel.hpp"
#include "ui_details_panel.h"

#include <QString>
#include <QtGlobal>

namespace sps::gui {

DetailsPanel::DetailsPanel(QWidget* parent)
    : QWidget(parent), ui_(new Ui::DetailsPanel)
{
    ui_->setupUi(this);
}

DetailsPanel::~DetailsPanel() { delete ui_; }

void DetailsPanel::clear() {
    ui_->textDisplay->clear();
}

void DetailsPanel::showResult(const core::ScanResult& r) {
    QString html;

    html += QString("<h3>%1:%2/%3 &mdash; %4</h3>")
        .arg(QString::fromStdString(r.target_host))
        .arg(r.port)
        .arg(QString::fromStdString(r.protocol))
        .arg(QString::fromStdString(r.service.name));

    html += QString("<b>Product:</b> %1 %2<br>")
        .arg(QString::fromStdString(r.service.product))
        .arg(QString::fromStdString(r.service.version));

    if (!r.service.extra_info.empty())
        html += QString("<b>Info:</b> %1<br>")
            .arg(QString::fromStdString(r.service.extra_info));

    html += QString("<b>RTT:</b> %1 ms<br>")
        .arg(r.rtt.count());
    html += QString("<b>Risk Score:</b> %1<br><br>")
        .arg(r.max_risk(), 0, 'f', 2);

    if (!r.service.banner_raw.empty()) {
        html += "<b>Banner:</b><pre style='padding:8px; border:1px solid #c0c0c0;'>";
        html += QString::fromStdString(r.service.banner_raw)
                    .toHtmlEscaped()
                    .left(512);
        html += "</pre><br>";
    }

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

    if (!r.cves.empty()) {
        html += "<h4>Vulnerabilities</h4>";
        for (const auto& cve : r.cves) {
            const double risk = static_cast<double>(cve.cvss_score) * cve.epss;
            html += QString(
                "<div style='margin-bottom:8px; padding:6px; "
                "border:1px solid #c0c0c0; border-radius:4px;'>"
                "<b>%1</b> &mdash; CVSS: %2 | "
                "<b>EPSS:</b> %3&#37; "
                "<span>Percentile: %4&#37;</span><br>"
                "<b>Risk Score:</b> %5<br>"
                "<b>Nuclei Verified:</b> %6<br>"
                "<small>%7</small></div>")
                .arg(QString::fromStdString(cve.cve_id))
                .arg(cve.cvss_score, 0, 'f', 1)
                .arg(qRound(cve.epss * 100.0))
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

} // namespace sps::gui
