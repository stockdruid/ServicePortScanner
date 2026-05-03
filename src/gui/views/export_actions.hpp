#pragma once

/*
GUI에서 스캔 결과를 파일로 내보내는 동작을 담당


사용자 Export Report 클릭
   ↓
ExportActions::exportResults(...)
   ↓
HTML / JSON / CSV 메뉴 표시
   ↓
저장 경로 선택
   ↓
선택한 writer로 파일 저장
   ↓
성공/실패 메시지 표시

*/

#include <QWidget>
#include <vector>
#include "core/result.hpp"

namespace sps::gui {

/*
parent는 dialog와 message box가 어느 창에 붙을지 정하는 Qt 부모 위젯.
results는 내보낼 스캔 결과 전체 목록.
*/
class ExportActions {
public:
    static void exportResults(QWidget* parent,
                              const std::vector<core::ScanResult>& results);
};

} 