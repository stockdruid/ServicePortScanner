#pragma once

#include <QMap>
#include <QPointF>
#include <QWidget>
#include <QtCharts/QChartView>
#include <vector>
#include "core/result.hpp"

/*정리
ChartsPanel의 역할은 세 가지입니다.

ScanResult 목록을 받아서 CVSS/EPSS scatter plot으로 시각화
Risk = CVSS × EPSS 기준으로 점 색상 분류
점 클릭 시 원본 서비스 결과 index를 signal로 알려줘서 DetailsPanel/테이블과 연동

핵심 흐름은 이렇게 보면 됩니다.
ScanResult 목록
   ↓ updateData()
EPSS/CVSS 점 생성
   ↓
Risk 등급별 색상 series에 추가
   ↓
사용자가 점 클릭
   ↓ on_scatter_clicked()
가장 가까운 PointInfo 찾기
   ↓
pointClicked(resultIndex) emit
   ↓
MainWindow가 DetailsPanel + table selection 갱신*/

namespace sps::gui {

class ChartsPanel : public QWidget {
    Q_OBJECT
public:
    explicit ChartsPanel(QWidget* parent = nullptr); //생성자 ; ChartsPanel은 QWidget을 상속
    
    // ScanResult 목록을 받아서 차트를 업데이트하는 함수
    /*현재는 MainWindow에서 dummy data를 만들어서 전달하는 형태지만
    나중에는 MainWindow가 스캔 결과를 받아서 모델에 넣고,
    모델이 변경될 때마다 ChartsPanel에 업데이트를 요청하는 형태로 변경 예정.*/
    void updateData(const std::vector<core::ScanResult>& results);

// 차트의 점을 클릭했을 때 발생시키는 signal
// MainWindow에서 이 signal을 받아서 해당 ScanResult의 상세 정보를 DetailsPanel에 표시하는 형태로 연결할 예정.
signals:
    void pointClicked(int resultIndex);

// 차트에서 클릭된 점과 ScanResult 목록의 인덱스를 매핑하기 위한 구조체와 멤버 변수  
private slots:
    void on_scatter_clicked(const QPointF& point);

// QtCharts의 scatter 점 클릭 이벤트를 받는 slot.
//클릭된 좌표를 받아서 실제 ScanResult 목록에서 가장 가까운 점을 찾아서 pointClicked signal을 발생시킴.
private:
    struct PointInfo {
        double epss;
        double cvss;
        int resultIndex;
    };

    QChartView* matrix_view_ = nullptr; // 차트 뷰(Qt 위젯)
    QChart*     matrix_      = nullptr; // 차트 데이터와 설정을 관리하는 객체(QtCharts의 QChart)
    std::vector<PointInfo> point_map_; // 차트의 각 점과 ScanResult 목록의 인덱스를 매핑하는 벡터
};

} 