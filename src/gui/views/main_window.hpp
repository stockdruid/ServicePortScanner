#pragma once

/*
테이블, 상세 패널, 차트, export 버튼을 한 화면에 연결하는 컨트롤러 역할을 하는 MainWindow 클래스 정의함.
*/

#include <QMainWindow>
#include <QSortFilterProxyModel>    //결과 테이블에 정렬/필터링 기능을 추가하기 위해 사용함.
#include "result_model.hpp"
#include "details_panel.hpp"
#include "charts_panel.hpp"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }    //UI 파일에서 생성된 MainWindow 클래스의 선언이 들어 있는 네임스페이스. UI 파일은 Qt Designer로 만든 GUI 레이아웃을 C++ 코드로 변환한 것으로, ui_mainwindow.h라는 헤더 파일에 MainWindow 클래스가 정의되어 있음. QT_BEGIN_NAMESPACE와 QT_END_NAMESPACE는 Qt 라이브러리에서 사용하는 매크로로, Qt 관련 코드를 Qt 네임스페이스 안에 넣기 위해 사용됨.
QT_END_NAMESPACE

namespace sps::gui {

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);   //QWidget를 부모로 받는 생성자.
    ~MainWindow();
    ResultModel* resultModel() const { return model_; }   //내부 ResultModel에 대한 접근자.

//테이블에서 행이 선택될 때마다 호출되는 슬롯 함수임. 선택된 행의 ScanResult를 가져와서 상세 패널과 차트 패널에 전달함.
private:
    Ui::MainWindow*         ui_     = nullptr;
    ResultModel*            model_  = nullptr;
    QSortFilterProxyModel*  proxy_  = nullptr;
    DetailsPanel*           detail_ = nullptr;
    ChartsPanel*            charts_ = nullptr;

    void setup_delegates();   //테이블의 특정 열에 대한 delegate 설정함.
    void setup_connections();    //테이블의 selection model과 on_row_selected 슬롯을 연결함.
    void load_dummy_data();   //테이블에 더미 데이터를 로드하는 함수. 실제 스캔 결과가 없을 때 UI 테스트용으로 사용함.
    void on_row_selected(const QModelIndex& current);   //선택된 행의 ScanResult를 가져와서 상세 패널과 차트 패널에 전달하는 슬롯 함수. 
};

} 