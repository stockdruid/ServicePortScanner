#pragma once

#include <QPainter>   //셀 배경과 텍스트를 직접 그릴 때
#include <QStyledItemDelegate>  //Qt의 테이블, 리스트 셀 렌더링을 커스터마이즈할 때 쓰는 클래스
#include <QtGlobal>   //qRound()를 쓰기 위해 필요
#include <algorithm>    //std::max()를 쓰기 위해 필요
#include "result_model.hpp"   //ResultModel::ColMaxEpss 컬럼 번호를 알기 위해 필요

namespace sps::gui {

class EpssDelegate : public QStyledItemDelegate {   //QStyledItemDelegate를 상속
    Q_OBJECT    //Qt meta-object 기능을 위한 매크로
public:
    //main window에서 epss 칼럼에 delegate를 붙임.
    using QStyledItemDelegate::QStyledItemDelegate;

    //테이블 셀 하나를 그릴 때 Qt가 호출하는 함수.
    //index는 모델의 어느 셀인지, option은 셀의 위치/크기 등 스타일 정보, painter는 그리기 도구.
    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;
    //delegate가 다른 컬럼에 잘못 적용되더라도 기본 표시가 되도록 하는 안전 장치
    QSize sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const override;

private:
    static QColor epss_color(double score); //EPSS 점수에 따라 색상 반환하는 헬퍼 함수.
};

} 

/*
QTableView가 EPSS 셀 렌더링 요청
   ↓
EpssDelegate::paint() 호출
   ↓
현재 컬럼이 ColMaxEpss인지 확인
   ↓
index.data(Qt::UserRole)로 max_epss 값 가져옴
   ↓
epss_color(epss)로 배경색 결정
   ↓
셀 배경을 색칠
   ↓
EPSS를 퍼센트 문자열로 중앙에 표시
*/