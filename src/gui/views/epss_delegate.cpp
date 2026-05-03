#include "epss_delegate.hpp"

namespace sps::gui {

void EpssDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const {
        //현재 칼럼이 EPSS 컬럼이 아니면 기본 delegate에게 그리도록 넘김.
        if (index.column() != ResultModel::ColMaxEpss &&
            index.column() != ResultModel::ColMaxPercentile) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }
        const QVariant val = index.data(Qt::UserRole); //실제 EPSS 값을 UserRole에서 가져옴.
        //값이 유효하지 않으면 (예: CVE가 없는 행) 기본 delegate에게 그리도록 넘김.
        if (!val.isValid()) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }
        //아래는 EPSS 값이 유효할 때의 커스텀 그리기 코드.
        const double epss = val.toDouble();
        QColor bg = epss_color(epss);
        painter->save();
        painter->fillRect(option.rect, bg);
        painter->setPen(QColor(255, 255, 255));
        QFont font = painter->font();
        font.setBold(true);
        painter->setFont(font);
        painter->drawText(option.rect, Qt::AlignCenter,
                          QString::number(qRound(epss * 100.0)) + "%");
        painter->restore();
    }

//너비 조절. 너비 최소를 설정함.
QSize EpssDelegate::sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const {
        auto s = QStyledItemDelegate::sizeHint(option, index);
        s.setWidth(std::max(s.width(), 60));
        return s;
    }

    
//EPSS 점수에 따른 색상 반환. 0.5 이상은 빨강, 0.1 이상은 노랑, 그 미만은 초록.
QColor EpssDelegate::epss_color(double score) {
        if (score >= 0.50) return QColor(180, 30, 30);
        if (score >= 0.10) return QColor(180, 170, 30);
        return QColor(30, 140, 30);
    }

} 
