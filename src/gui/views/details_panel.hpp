#pragma once

/*
GUI 오른쪽의 상세 정보 패널을 담당합니다.(오른쪽 패널에 HTML로 렌더링하여 보여줌.)
테이블 행을 클릭하거나 차트 점을 클릭하면, 해당 ScanResult를 받아서 서비스 정보, 배너, OS/CDN/JA4 정보, CVE 목록을 HTML 형태로 보여줍니다.

해당 패널의 존재 이유는 ResultModel은 테이블용 요약 데이터를 보여줍니다.
하지만 한 행에 모든 정보를 다 넣기에는 너무 많습니다.
그래서 DetailsPanel은 선택된 서비스 하나를 자세히 보여주는 역할을 합니다.
*/

#include <QWidget>    //DetailsPanel이 QWidget을 상속하므로 <QWidget>이 필요
#include <QString>    //HTML 문자열을 만들 때 QString을 사용
#include "core/result.hpp"

/*
Ui::DetailsPanel 클래스를 전방 선언하는 코드.
.ui 파일을 빌드하면 Qt가 자동으로 ui_details_panel.h를 생성하고 Ui::DetailsPanel 클래스가 생기게 된다.

전방 선언을 하는 이유는 UI가 변경되었을 때 details_panel.h를 include 하고 있는 프로젝트 내의 수많은 다른 소스 파일들까지
전부 다시 컴파일하지 않고 포인터로만 참고하여 화면(.ui)을 아무리 수정해도 .cpp 파일 딱 하나만 다시 컴파일하면 되기 때문임.
*/
QT_BEGIN_NAMESPACE
namespace Ui { class DetailsPanel; }
QT_END_NAMESPACE

namespace sps::gui {

class DetailsPanel : public QWidget {
    Q_OBJECT
public:
    explicit DetailsPanel(QWidget* parent = nullptr);
    ~DetailsPanel();    //소멸자
    void showResult(const core::ScanResult& r);   //ScanResult를 받아서 상세 HTML을 만들고 화면에 표시

private:
    Ui::DetailsPanel* ui_ = nullptr;    //.ui에서 생성된 위젯들에 접근하기 위한 포인터.
    static QString cvss_html_color(float score); //cvss 점수에 따라 HTML 배경색 반환.
    static QString epss_html_color(double epss); //epss 점수에 따라 HTML 배경색 반환.
};

} 