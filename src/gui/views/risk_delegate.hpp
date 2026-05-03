#pragma once

/*
Risk는 현재 CVSS × EPSS로 계산됩니다. 즉 취약점 자체의 심각도와 실제 악용 가능성을 곱해서 우선순위 점수로 보여주는 값입니다.

risk_delegate의 존재 이유
:ResultModel은 Risk 값을 숫자로 제공합니다.
하지만 그냥 9.51, 4.50, 0.49 같은 숫자로만 보면 한눈에 우선순위가 잘 안 들어옵니다.

그래서 RiskDelegate는 Risk 컬럼을 직접 그립니다.

위험도가 높으면 빨간색, 중간이면 주황/노랑,낮으면 회색, 숫자는 흰색 bold로 중앙 표시
*/

#include <QPainter>
#include <QStyledItemDelegate>
#include <algorithm>
#include "result_model.hpp"

namespace sps::gui {

class RiskDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    using QStyledItemDelegate::QStyledItemDelegate; //부모 클래스 생성자를 그대로 사용

    //테이블의 셀 하나를 그릴 때 Qt가 호출됨.
    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;

    //셀의 권장 크기를 알려주는 함수.
    QSize sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const override;

//risk 점수에 따른 배경색을 반환하는 헬퍼 함수.
//7.0 이상은 빨강, 3.0 이상은 주황, 1.0 이상은 노랑, 그 미만은 회색.                   
private:
    static QColor risk_color(double score);
};

} 