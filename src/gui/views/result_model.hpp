#pragma once

#include <QAbstractTableModel>
#include <vector>

#include "core/result.hpp"

namespace sps::gui {

class ResultModel : public QAbstractTableModel {    //QAbstractTableModel을 상속받아서 테이블 모델로 사용.
    Q_OBJECT

public:
    //테이블의 열을 나타내는 enum(순서).
    enum Column {
        ColPort = 0,
        ColService,
        ColProduct,
        ColVersion,
        ColCveCount,
        ColMaxCvss,
        ColMaxEpss,
        ColMaxPercentile,
        ColRisk,
        ColVerified,
        ColJa4s,
        ColJa4x,
        ColCdn,
        ColOs,
        ColCount
    };

    explicit ResultModel(QObject* parent = nullptr); //생성자

    int rowCount(const QModelIndex& = {}) const override;     //행 개수 반환. results_ 벡터의 크기를 반환.

    int columnCount(const QModelIndex& = {}) const override; //열 개수 반환. enum Column에서 정의한 ColCount로 고정.

    //열 헤더 이름 반환. orientation이 Horizontal인 경우에만 열 이름을 반환하고, 그렇지 않으면 빈 QVariant 반환.
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    //셀 데이터 반환. index가 유효하지 않거나 행 번호가 results_ 범위를 벗어나면 빈 QVariant 반환.
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

    //새로운 스캔 결과 추가.
    void appendResult(core::ScanResult result);

    //스캔 결과 전체 목록 교체.
    void setResults(std::vector<core::ScanResult> results);

    //특정 행의 ScanResult 반환.
    const core::ScanResult& resultAt(int row) const;

    //전체 결과 목록 반환.
    const std::vector<core::ScanResult>& allResults() const;

    //초기화.
    void clear();

private:
    std::vector<core::ScanResult> results_;     //실제 스캔 결과 데이터를 저장하는 벡터. 각 ScanResult는 테이블의 한 행에 해당.
};

} 
