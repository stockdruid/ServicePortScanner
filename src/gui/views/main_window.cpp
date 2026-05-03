#include "main_window.hpp"
#include "ui_main_window.h"
#include "cvss_delegate.hpp"
#include "epss_delegate.hpp"
#include "risk_delegate.hpp"
#include "export_actions.hpp"
#include "dummy_data.hpp"

#include <QAbstractItemView>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QPushButton>
#include <QVBoxLayout>

namespace sps::gui {

MainWindow::MainWindow(QWidget* parent)   //QWidget를 부모로 받는 생성자임.
    : QMainWindow(parent), ui_(new Ui::MainWindow)      
{
  //레이아웃 설정
    ui_->setupUi(this);
    ui_->leftLayout->setStretch(0, 0);
    ui_->leftLayout->setStretch(1, 1);
    ui_->leftLayout->setStretch(2, 0);
    ui_->leftLayout->setStretch(3, 0);
    ui_->rightLayout->setStretch(0, 0);
    ui_->rightLayout->setStretch(1, 1);
    ui_->rightLayout->setStretch(2, 0);

    //모델과 프록시 모델 생성 및 테이블에 연결
    model_ = new ResultModel(this);
    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(model_);
    proxy_->setSortRole(Qt::UserRole);

    //테이블 설정
    ui_->tableView->setModel(proxy_);
    ui_->tableView->setSortingEnabled(true);
    ui_->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui_->tableView->setAlternatingRowColors(true);
    ui_->tableView->horizontalHeader()->setStretchLastSection(true);
    ui_->tableView->verticalHeader()->setDefaultSectionSize(28);


    detail_ = new DetailsPanel(this); //상세 패널 객체를 생성함.

    //UI 파일에서 detailsText라는 QTextEdit이 상세 패널 자리의 placeholder로 되어 있는데, 그 자리에 detail_을 넣어줌.
    auto* rightLayout = ui_->detailsText->parentWidget()->layout();    
    rightLayout->replaceWidget(ui_->detailsText, detail_);  //placeholder 제거.
    delete ui_->detailsText;    //placeholder 위젯 삭제.

    //ChartsPanel은 .ui 파일 안에 chartsContainer라는 QWidget으로 placeholder 되어 있음.
    //그 안에 ChartsPanel을 동적으로 생성하여 넣어줌. 실제 차트는 런타임에 코드로 넣음.
    charts_ = new ChartsPanel(this);
    auto* chartsLayout = new QVBoxLayout(ui_->chartsContainer);
    chartsLayout->setContentsMargins(0, 0, 0, 0);
    chartsLayout->addWidget(charts_);   //차트 패널을 chartsContainer에 넣음.

    ui_->splitter->setSizes({800, 350});  //초기 분할 비율 설정. 왼쪽 테이블이 더 넓게 보이도록.

    setup_delegates();    //테이블의 특정 열에 대한 delegate 설정.
    setup_connections();    //테이블 선택, export 버튼, 차트 클릭 등과 슬롯 함수를 연결.
    //일단 더미 데이터를 로드해서 UI가 제대로 보이는지 확인.
    //실제 스캔 결과가 생기면 이 부분은 제거하거나 다른 데이터 로딩 함수로 대체할 예정.
    load_dummy_data(); 
}

MainWindow::~MainWindow() {
    delete ui_;
}

//테이블의 CVSS, EPSS, Risk 열에 대해 각각 커스텀 delegate를 설정하는 함수.
void MainWindow::setup_delegates() {
    auto* cvss_del = new CvssDelegate(this);
    ui_->tableView->setItemDelegateForColumn(ResultModel::ColMaxCvss, cvss_del);
    auto* epss_del = new EpssDelegate(this);
    ui_->tableView->setItemDelegateForColumn(ResultModel::ColMaxEpss, epss_del);
    auto* percentile_del = new EpssDelegate(this);
    ui_->tableView->setItemDelegateForColumn(ResultModel::ColMaxPercentile, percentile_del);
    auto* risk_del = new RiskDelegate(this);
    ui_->tableView->setItemDelegateForColumn(ResultModel::ColRisk, risk_del);
    ui_->tableView->sortByColumn(ResultModel::ColRisk, Qt::DescendingOrder);
}

//테이블의 행 선택, export 버튼 클릭, 차트 점 클릭 등과 슬롯 함수를 연결하는 함수.
void MainWindow::setup_connections() {
    connect(ui_->tableView->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::on_row_selected);
    connect(ui_->btnExport, &QPushButton::clicked, this, [this]() {
        ExportActions::exportResults(this, model_->allResults());
    });
    //charts_pannle에서 차트 점 클릭 → DetailsPanel 갱신 → 테이블 행 선택까지 이어집니다.
    connect(charts_, &ChartsPanel::pointClicked, this, [this](int idx) {
        detail_->showResult(model_->resultAt(idx));
        QModelIndex proxyIdx = proxy_->mapFromSource(model_->index(idx, 0));
        if (proxyIdx.isValid()) ui_->tableView->setCurrentIndex(proxyIdx);
    });
}

//더미 데이터를 로드하는 함수. 실제 스캔 결과가 생기면 이 부분은 제거하거나 다른 데이터 로딩 함수로 대체할 예정임.
void MainWindow::load_dummy_data() {
    model_->setResults(sps::test::make_dummy_results());
    charts_->updateData(model_->allResults());
    ui_->tableView->sortByColumn(ResultModel::ColRisk, Qt::DescendingOrder);
}

//테이블에서 행이 선택될 때마다 해당 CVE의 상세 정보를 DetailsPanel에 보여주는 슬롯 함수.
void MainWindow::on_row_selected(const QModelIndex& current) {
    if (!current.isValid()) return;
    QModelIndex src = proxy_->mapToSource(current);
    detail_->showResult(model_->resultAt(src.row()));
}

} 
