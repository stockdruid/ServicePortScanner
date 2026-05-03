#include "charts_panel.hpp"

#include <QPainter>
#include <QVBoxLayout>
#include <QtCharts/QScatterSeries>  //점 그래프
#include <QtCharts/QValueAxis>  //값 축 (X축과 Y축)

#include <limits>  //클릭된 점과 가장 가까운 점을 찾을 때 거리 계산에 사용

namespace sps::gui {

//익명 네임스페이스는 이 파일 내에서만 사용할 함수나 변수를 정의할 때 사용. 외부에서 접근 불가.
namespace {

//차트에 표시할 서비스인지를 판단. 기획안 대로 5개 서비스만 정의
bool is_probe_result(const core::ScanResult& r) {
    const auto& service = r.service.name;
    return service == "ssh" ||
           service == "http" ||
           service == "tls" ||
           service == "ftp" ||
           service == "smtp";
}

//scatter series를 생성하는 헬퍼 함수. 시리즈 이름과 색상을 받아서 QScatterSeries 객체를 만들어 반환.
QScatterSeries* make_series(const QString& name, const QColor& color) {
    auto* series = new QScatterSeries;
    series->setName(name);
    series->setMarkerSize(12.0);
    series->setColor(color);
    series->setBorderColor(QColor(255, 255, 255));
    return series;
}

// Risk 기준 (Risk의 범위는 0.0 ~ 10.0 ; result.hpp의 ScanResult::max_risk() 참조)
QScatterSeries* series_for_risk(double risk,
                                QScatterSeries* critical,
                                QScatterSeries* high,
                                QScatterSeries* medium,
                                QScatterSeries* low) {
    if (risk >= 7.0) return critical;
    if (risk >= 3.0) return high;
    if (risk >= 1.0) return medium;
    return low;
}

} // namespace

//ChartsPannel 초기화 -> 생성 -> 적용
ChartsPanel::ChartsPanel(QWidget* parent) : QWidget(parent) {
    matrix_ = new QChart;
    matrix_->setTitle("Risk Priority Matrix (CVSS x EPSS)");
    matrix_->setTheme(QChart::ChartThemeDark);
    matrix_->setAnimationOptions(QChart::SeriesAnimations); //데이터가 표시될 때 series 별로 애니메이션 효과 적용
    matrix_->setMargins(QMargins(12, 18, 18, 12));

    //오른쪽에 범례 표시. 범례는 각 시리즈의 이름과 색상을 보여주는 역할.
    //(오른쪽에 위치한 Critical, High, Medium, Low)
    matrix_->legend()->setVisible(true);
    matrix_->legend()->setAlignment(Qt::AlignRight);

    matrix_view_ = new QChartView(matrix_); // QChartView는 QChart를 화면에 표시하는 역할을 하는 위젯.
    matrix_view_->setRenderHint(QPainter::Antialiasing); //그래픽 렌더링 품질 향상을 위해 안티앨리어싱 적용
    matrix_view_->setMinimumHeight(260); //차트 영역이 너무 작아지는 것을 방지하기 위해 최소 높이 설정

    //ChartsPanel 내부에 레이아웃을 만들고, 그 안에 차트 뷰를 넣음.
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(matrix_view_, 1);
}

// 차트 데이터를 새로 그리는 함수.
// MainWindow에서 ScanResult 목록을 받아서 차트를 업데이트할 때 호출됨.ChartsPanel 내부에 세로 레이아웃을 만들고, 그 안에 차트 뷰를 넣음.
void ChartsPanel::updateData(const std::vector<core::ScanResult>& results) {
    //점과 축 삭제
    matrix_->removeAllSeries();
    for (auto* axis : matrix_->axes()) matrix_->removeAxis(axis);

    //risk 등급별 series 생성
    auto* critical = make_series("Critical", QColor(180, 30, 30));
    auto* high = make_series("High", QColor(200, 120, 20));
    auto* medium = make_series("Medium", QColor(180, 170, 30));
    auto* low = make_series("Low", QColor(80, 80, 80));

    point_map_.clear(); //점 클릭 매핑을 초기화.
    int idx = 0; //현재 results에서 몇 번째 항목인지 추적하기 위함.

    //점 클릭 매핑을 위해서, 각 ScanResult를 순회하면서 차트에 점을 추가하고,
    //point_map_에 해당 점의 EPSS, CVSS, 그리고 ScanResult 목록에서의 인덱스를 저장.
    for (const auto& r : results) {
      //probe 대상 서비스가 아니면 제외 && CVE가 없으면 제외
        if (!is_probe_result(r) || r.cves.empty()) {
            ++idx;
            continue;
        }

        auto* series = series_for_risk(r.max_risk(), critical, high, medium, low); //max_risk() 기준으로 색상 그룹 선택
        series->append(r.max_epss(), r.max_cvss()); //X축에 max_epss(), Y축에 max_cvss() 점 추가
        point_map_.push_back({r.max_epss(), r.max_cvss(), idx}); //같은 좌표와 원본 index를 point_map_에 저장
        ++idx;
    }

    //series를 차트에 추가. Critical, High, Medium, Low 순서로 추가하여 범례에도 같은 순서로 표시되도록 함.
    matrix_->addSeries(critical);
    matrix_->addSeries(high);
    matrix_->addSeries(medium);
    matrix_->addSeries(low);

    //click 이벤트 연결. 각 series의 점이 클릭되었을 때 on_scatter_clicked slot이 호출되도록 연결.
    for (auto* s : matrix_->series()) {
        auto* scatter = qobject_cast<QScatterSeries*>(s);
        if (scatter) {
            connect(scatter, &QScatterSeries::clicked,
                    this, &ChartsPanel::on_scatter_clicked);
        }
    }

    //x축 설정
    auto* axisX = new QValueAxis;
    axisX->setRange(0.0, 1.0);
    axisX->setTickCount(5);
    axisX->setLabelFormat("%.1f");
    axisX->setTitleText("EPSS (Exploit Probability)");
    matrix_->addAxis(axisX, Qt::AlignBottom);

    //y축 설정
    auto* axisY = new QValueAxis;
    axisY->setRange(0.0, 10.0);
    axisY->setTickCount(5);
    axisY->setLabelFormat("%.1f");
    axisY->setTitleText("CVSS Score");
    matrix_->addAxis(axisY, Qt::AlignLeft);

    for (auto* series : matrix_->series()) {
        series->attachAxis(axisX);
        series->attachAxis(axisY);
    }
}

//scatter plot의 점을 클릭했을 때 호출됨.
void ChartsPanel::on_scatter_clicked(const QPointF& point) { //point는 클릭된 좌표 (EPSS, CVSS)
    double minDist = std::numeric_limits<double>::max();
    int bestIdx = -1; // 가장 가까운 점을 찾기 위한 초기값.

    //저장된 점들과 클릭 좌표 사이의 거리를 계산.
    //idx는 results '벡터'의 현재 위치를 나태내기 때문에 아래와 같이 계산.
    for (const auto& p : point_map_) {
        double dx = p.epss - point.x();
        double dy = (p.cvss - point.y()) / 10.0; //epss와 cvss의 스케일 차이 때문에 비율 맞춤.
        double dist = dx * dx + dy * dy;
        if (dist < minDist) {
            minDist = dist;
            bestIdx = p.resultIndex;
        }
    }
    if (bestIdx >= 0) emit pointClicked(bestIdx);
}

} 
