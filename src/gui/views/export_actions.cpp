#include "export_actions.hpp"

#include <QAction>    // 메뉴 항목 HTML/JSON/CSV를 만들 때 사용
#include <QCursor>    // 현재 마우스 위치에 메뉴를 띄우기 위해 사용
#include <QFileDialog>    // 파일 저장 대화상자를 띄우기 위해 사용
#include <QMenu>    // export 형식 선택 메뉴를 만들 때 사용
#include <QMessageBox>  //성공, 실패 알림창
#include <exception>    //파일 저장 실패 시 std::exception을 잡기 위해 필요.

//아래는 실제 파일 내용을 쓰는 모듈
#include "report/html_writer.hpp"
#include "report/json_writer.hpp"
#include "report/csv_writer.hpp"

namespace sps::gui {

void ExportActions::exportResults(QWidget* parent,
                              const std::vector<core::ScanResult>& results)
    {
      //사용자에게 HTML/JSON/CSV 중 어떤 형식으로 내보낼지 선택하게 하는 메뉴를 띄움.
        QMenu menu(parent);
        QAction* html = menu.addAction("HTML Report");
        QAction* json = menu.addAction("JSON");
        QAction* csv = menu.addAction("CSV");

        //현재 마우스 위치에 메뉴를 띄우고 사용자가 선택한 항목을 가져옴.
        QAction* selected = menu.exec(QCursor::pos());
        if (!selected) return;

        QString title;    //파일 저장 제목
        QString defaultName;  //기본 파일명
        QString filter;     //파일 확장자 필터
        QString suffix;   //자동으로 붙일 확장자
        if (selected == html) {
            title = "Export HTML Report";
            defaultName = "scan_report.html";
            filter = "HTML (*.html)";
            suffix = ".html";
        } else if (selected == json) {
            title = "Export JSON";
            defaultName = "scan_report.json";
            filter = "JSON (*.json)";
            suffix = ".json";
        } else if (selected == csv) {
            title = "Export CSV";
            defaultName = "scan_report.csv";
            filter = "CSV (*.csv)";
            suffix = ".csv";
        
        //이외의 경우 안전하게 종료.    
        } else {
            return;
        }

        //저장 경로
        QString path = QFileDialog::getSaveFileName(parent, title, defaultName, filter);
        if (path.isEmpty()) return;   //사용자가 저장 취소를 누르면 path가 비기 때문.
        if (!path.endsWith(suffix, Qt::CaseInsensitive)) path += suffix;  //확장자가 없으면 자동으로 붙임.

        //선택된 형식에 따라 writer를 호출해서 파일로 저장.
        try {
            if (selected == html) {
                report::HtmlWriter::write(path.toStdString(), results);
            } else if (selected == json) {
                report::JsonWriter::write(path.toStdString(), results);
            } else {
                report::CsvWriter::write(path.toStdString(), results);
            }
          //파일 읽기, 쓰기 과정에서 문제가 생기면 예외가 발생할 수 있으므로 잡아서 사용자에게 알림.  
        } catch (const std::exception& e) {
            QMessageBox::critical(parent, "Export Error",
                                  QString("Failed to write file:\n%1\n\n%2")
                                      .arg(path, QString::fromUtf8(e.what())));
            return;
        }

        //저장 완료 메시지를 띄움.
        QMessageBox::information(parent, "Export Complete",
                                 "Report exported to:\n" + path);
    }

} 