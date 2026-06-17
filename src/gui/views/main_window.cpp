#include "main_window.hpp"
#include "ui_main_window.h"
#include "cvss_delegate.hpp"
#include "epss_delegate.hpp"
#include "risk_delegate.hpp"
#include "export_actions.hpp"
#include "dummy_data.hpp"
#include "scan_dialog.hpp"
#include "settings_dialog.hpp"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QFile>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPushButton>
#include <QStatusBar>
#include <QVBoxLayout>

#include <chrono>
#include <filesystem>

namespace sps::gui {

namespace {

// data/<filename> 을 다음 순서로 찾음:
//  1. CWD/data/  (개발 시 repo root 에서 실행)
//  2. exe/../../../data/  (build_gui/src/gui/ 에서 실행 — 개발 빌드)
//  3. exe/data/  (배포 시 .exe 옆에 data/ 디렉토리 동봉)
// 못 찾으면 빈 path 반환 — DB 로더가 알아서 빈 결과 처리.
std::filesystem::path find_data_path(const QString& filename) {
    const QStringList candidates = {
        QStringLiteral("data/") + filename,
        QApplication::applicationDirPath() + QStringLiteral("/../../../data/") + filename,
        QApplication::applicationDirPath() + QStringLiteral("/data/") + filename,
    };
    for (const auto& path : candidates) {
        if (QFile::exists(path)) {
            return std::filesystem::path(path.toStdString());
        }
    }
    return {};
}

} // namespace

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

    // ScanController — UI 스레드에서 생성. 저장된 설정(rate/timeout) 즉시 반영.
    controller_ = new ScanController(this);
    {
        const auto s = load_settings();
        controller_->setRate(s.rate_pps);
        controller_->setTimeout(std::chrono::milliseconds(s.timeout_ms));
    }

    // 백엔드 DB 자동 주입.
    // - probes: data/probes.json 발견 시 외부 DB, 아니면 임베디드 폴백 (HTTP/SSH/FTP/SMTP/TLS).
    // - cve / epss: data/ 파일 발견 시만 활성화 (없으면 connect-only + service 식별만).
    // - cdn: 내장 CIDR DB 항상 사용 (Cloudflare/Fastly/Akamai 등).
    {
        const auto probes_path = find_data_path(QStringLiteral("probes.json"));
        controller_->setProbes(sps::probes::default_probes(probes_path.string()));
        controller_->setCdnDb(sps::fp::CdnDatabase::load_default());

        QStringList loaded;
        loaded << QStringLiteral("probes")
               << QStringLiteral("CDN");

        if (auto p = find_data_path(QStringLiteral("nvd_min.json")); !p.empty()) {
            controller_->setCveDb(sps::fp::CveDb::load(p));
            loaded << QStringLiteral("CVE");
        }
        if (auto p = find_data_path(QStringLiteral("epss_min.csv")); !p.empty()) {
            controller_->setEpssDb(sps::fp::EpssDb::load(p));
            loaded << QStringLiteral("EPSS");
        }
        statusBar()->showMessage(
            QStringLiteral("Loaded: %1").arg(loaded.join(", ")), 5000);
    }

    setup_delegates();    //테이블의 특정 열에 대한 delegate 설정.
    setup_connections();    //테이블 선택, export 버튼, 차트 클릭 등과 슬롯 함수를 연결.
    setup_scan_menu();    //File 메뉴에 데모 스캔 액션 등록.
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

    // ScanController → model/charts/status 연결.
    // resultReady: 새 ScanResult 가 도착하면 model 에 append (UI 스레드 보장).
    connect(controller_, &ScanController::resultReady,
            model_, &ResultModel::appendResult);
    connect(controller_, &ScanController::progressChanged,
            this, [this](int done, int total) {
        statusBar()->showMessage(
            QStringLiteral("Scanning… %1/%2").arg(done).arg(total));
    });
    connect(controller_, &ScanController::scanFinished, this, [this]() {
        charts_->updateData(model_->allResults());
        statusBar()->showMessage(
            QStringLiteral("Scan complete (%1 results)")
                .arg(model_->allResults().size()), 5000);
    });
    connect(controller_, &ScanController::scanError, this,
            [this](const QString& msg) {
        QMessageBox::warning(this, "Scan Error", msg);
        statusBar()->clearMessage();
    });
}

// File / Edit 메뉴 등록.
void MainWindow::setup_scan_menu() {
    auto* fileMenu = menuBar()->addMenu(QStringLiteral("&File"));
    auto* scanAct  = fileMenu->addAction(QStringLiteral("New Scan…"));
    scanAct->setShortcut(QKeySequence::New);   // Ctrl+N
    connect(scanAct, &QAction::triggered, this, &MainWindow::open_scan_dialog);
    auto* demoAct  = fileMenu->addAction(QStringLiteral("Scan localhost (top 10)"));
    connect(demoAct, &QAction::triggered, this, &MainWindow::start_demo_scan);
    fileMenu->addSeparator();
    auto* quitAct  = fileMenu->addAction(QStringLiteral("Quit"));
    connect(quitAct, &QAction::triggered, this, &QMainWindow::close);

    auto* editMenu = menuBar()->addMenu(QStringLiteral("&Edit"));
    auto* settingsAct = editMenu->addAction(QStringLiteral("Settings…"));
    settingsAct->setShortcut(QKeySequence::Preferences);
    connect(settingsAct, &QAction::triggered, this, &MainWindow::open_settings);
}

// 임의 target / ports 입력 다이얼로그 → scope 체크 통과 시 스캔 시작.
void MainWindow::open_scan_dialog() {
    if (controller_->isScanning()) {
        QMessageBox::information(this, "Scan",
            QStringLiteral("A scan is already in progress."));
        return;
    }
    ScanDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) return;
    const auto req = dlg.request();
    statusBar()->showMessage(
        QStringLiteral("Starting scan: %1 (%2 ports)…")
            .arg(req.target).arg(req.ports.size()));
    controller_->startScan(req.target, req.ports);
}

// Settings 다이얼로그 — 변경 시 controller + 테마에 즉시 반영.
void MainWindow::open_settings() {
    SettingsDialog dlg(load_settings(), this);
    if (dlg.exec() != QDialog::Accepted) return;

    const auto s = dlg.settings();
    save_settings(s);
    apply_theme(*qApp, s.theme);
    charts_->setTheme(s.theme == Theme::Dark);
    controller_->setRate(s.rate_pps);
    controller_->setTimeout(std::chrono::milliseconds(s.timeout_ms));
    statusBar()->showMessage(QStringLiteral("Settings updated"), 3000);
}

// localhost top-10 포트 데모 스캔 트리거.
void MainWindow::start_demo_scan() {
    if (controller_->isScanning()) {
        QMessageBox::information(this, "Scan",
            QStringLiteral("A scan is already in progress."));
        return;
    }
    QVector<quint16> ports{21, 22, 25, 80, 110, 143, 443, 587, 993, 8080};
    statusBar()->showMessage(QStringLiteral("Starting localhost demo scan…"));
    controller_->startScan(QStringLiteral("127.0.0.1"), ports);
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
