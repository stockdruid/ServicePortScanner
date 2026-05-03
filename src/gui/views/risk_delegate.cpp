#include "risk_delegate.hpp"

namespace sps::gui {

//Paint 함수는 테이블의 셀 하나를 그릴 때 Qt가 호출하는 함수.
void RiskDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const {
        //현재 컬럼이 Risk 컬럼이 아니면 기본 delegate에게 그리도록 넘김.
        if (index.column() != ResultModel::ColRisk) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        const QVariant val = index.data(Qt::UserRole); //UserRole에서 Risk 값을 가져옴.
        //값이 없으면 기본 렌더링 값 반환.
        if (!val.isValid()) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        const double risk = val.toDouble();   //risk 값을 double로 변환.
        QColor bg = risk_color(risk);   //risk 점수에 따른 배경색 가져옴. risk_color()는 아래에 정의.

        //painter로 셀 배경과 텍스트를 그림.
        painter->save();
        painter->fillRect(option.rect, bg);
        painter->setPen(QColor(255, 255, 255));
        QFont font = painter->font();
        font.setBold(true);
        painter->setFont(font);
        painter->drawText(option.rect, Qt::AlignCenter, QString::number(risk, 'f', 2));
        painter->restore();
    }

//셀의 권장 크기를 반환함.
QSize RiskDelegate::sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const {
        auto s = QStyledItemDelegate::sizeHint(option, index);
        s.setWidth(std::max(s.width(), 70));    //셀의 최소 넓이 지정.
        return s;
    }

//risk 점수에 따른 배경색을 반환하는 헬퍼 함수.
QColor RiskDelegate::risk_color(double score) {
        if (score >= 7.0) return QColor(180, 30, 30);
        if (score >= 3.0) return QColor(200, 120, 20);
        if (score >= 1.0) return QColor(180, 170, 30);
        return QColor(80, 80, 80);
    }
} 