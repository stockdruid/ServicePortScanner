#include "cvss_delegate.hpp"


namespace sps::gui {

void CvssDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const {

        //CVSS 열이 아니면 기본 delegat에게 넘김.
        if (index.column() != ResultModel::ColMaxCvss) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        const QVariant val = index.data(Qt::UserRole); //UserRole은 정렬/색상 계산용 원본 숫자를 위해 사용.
        //CVE가 없는 행이면 CVSS 값이 비어 있을 수 있으니까 기본 렌더링 처리.
        if (!val.isValid()) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        const float cvss = val.toFloat();
        const QColor bg = cvss_color(cvss); //cvss 점수에 따른 배경색 가져옴. 맨 아래에 정의.

        //painter로 그림.
        painter->save(); 
        painter->fillRect(option.rect, bg);
        painter->setPen(QColor(255, 255, 255));
        QFont font = painter->font();
        font.setBold(true);
        painter->setFont(font);
        painter->drawText(option.rect, Qt::AlignCenter,
                          QString::number(cvss, 'f', 1));
        painter->restore();
    }

QSize CvssDelegate::sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const {
        auto s = QStyledItemDelegate::sizeHint(option, index); //delegate가 계산한 크기를 가져옴.
        s.setWidth(std::max(s.width(), 60)); //너비가 너무 좁으면 최소 60으로 늘림.
        return s;
    }

QColor CvssDelegate::cvss_color(float score) {
        if (score >= 9.0f) return QColor(180, 30, 30);
        if (score >= 7.0f) return QColor(200, 120, 20);
        if (score >= 4.0f) return QColor(180, 170, 30);
        if (score >  0.0f) return QColor(80, 80, 80);
        return QColor(50, 50, 50);
    }

} // namespace sps::gui
