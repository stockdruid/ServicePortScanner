#pragma once

#include <QPainter>
#include <QStyledItemDelegate>  //Qt의 테이블/리스트 셀 렌더링을 커스터마이즈할 때 쓰는 클래스
#include <algorithm>
#include "result_model.hpp"

/*
cvss_delegate의 존재 이유
Qt의 QTableView는 기본적으로 모델에서 받은 값을 그냥 텍스트로 보여줍니다.
그런데 CVSS 점수는 단순 숫자보다, 심각도별 색상으로 보여주는 게 훨씬 보기 좋습니다.
그래서 CvssDelegate가 QStyledItemDelegate를 상속해서 CVSS 셀만 직접 그립니다.


MainWindow에서 테이블의 CVSS 열에 CvssDelegate를 설정하면,
그 열의 셀들은 CvssDelegate::paint()가 호출되어서 CVSS 점수에 따라 색상이 칠해진 원형 배경과 함께 점수가 표시됩니다.


아래는 MainWindow에서 CvssDelegate를 설정하는 코드입니다.

auto* cvss_del = new CvssDelegate(this);
ui_->tableView->setItemDelegateForColumn(ResultModel::ColMaxCvss, cvss_del);

즉 ResultModel::ColMaxCvss 컬럼은 기본 렌더링 대신 CvssDelegate::paint()가 그립니다.
*/

namespace sps::gui {

class CvssDelegate : public QStyledItemDelegate {
    Q_OBJECT //Qt meta-object 기능을 쓰기 위한 매크로
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    //테이블의 셀 하나를 그릴 때 Qt가 호출됨.
    //index는 모델의 어느 셀인지, option은 셀의 위치/크기 등 스타일 정보, painter는 그리기 도구.
    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;

    //셀의 권장 크기를 알려주는 함수.
    QSize sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const override;

private:
    //CVSS 점수에 따라 색상 반환하는 핼퍼 함수.
    //CVSS 9.0 이상은 빨강, 7.0 이상은 주황, 4.0 이상은 노랑, 0보다 크면 회색, 0이면 더 어두운 회색.
    static QColor cvss_color(float score);
};

} 
