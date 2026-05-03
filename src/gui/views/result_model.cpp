#include "result_model.hpp"

#include <utility>

namespace sps::gui {

ResultModel::ResultModel(QObject* parent) //부모 객체를 QAbstractTableModel 생성자에 넘김.
        : QAbstractTableModel(parent) {}

int ResultModel::rowCount(const QModelIndex&) const {
        return static_cast<int>(results_.size());   //reulsts_ 에 들어 있는 스캔 결과 개수를 행 개수로 반환.
    }

int ResultModel::columnCount(const QModelIndex&) const {
        return ColCount;    //열 개수는 enum Column에서 정의한 ColCount로 고정.
    }

//헤더 이름 반환. orientation이 Horizontal인 경우에만 열 이름을 반환하고, 그렇지 않으면 빈 QVariant 반환.
QVariant ResultModel::headerData(int section, Qt::Orientation orientation,
                        int role) const {
        if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
            return {};

        switch (static_cast<Column>(section)) {
            case ColPort:      return "Port";
            case ColService:   return "Service";
            case ColProduct:   return "Product";
            case ColVersion:   return "Version";
            case ColCveCount:  return "CVEs";
            case ColMaxCvss:   return "CVSS";
            case ColMaxEpss:   return "EPSS";
            case ColMaxPercentile: return "Percentile";
            case ColRisk:      return "Risk";
            case ColVerified:  return "Verified";
            case ColJa4s:      return "JA4S";
            case ColJa4x:      return "JA4X";
            case ColCdn:       return "CDN";
            case ColOs:        return "OS";
            default:           return {};  //정의되지 않는 열 번호인 경우 빈 QVariant 반환.
        }
    }

//셀 데이터를 반환. index가 유효하지 않거나 행 번호가 results_ 범위를 벗어나면 빈 QVariant 반환.
QVariant ResultModel::data(const QModelIndex& index, int role) const {
        if (!index.isValid() || index.row() >= static_cast<int>(results_.size()))
            return {};

        const auto& r = results_[index.row()];

        if (role == Qt::DisplayRole) {
            switch (static_cast<Column>(index.column())) {
                case ColPort:      return r.port;
                case ColService:   return QString::fromStdString(r.service.name);
                case ColProduct:   return QString::fromStdString(r.service.product);
                case ColVersion:   return QString::fromStdString(r.service.version);
                case ColCveCount:  return static_cast<int>(r.cves.size());
                case ColMaxCvss:   return r.cves.empty() ? QVariant{} : QVariant{r.max_cvss()};
                case ColMaxEpss:   return r.cves.empty() ? QVariant{} : QVariant{r.max_epss()};
                case ColMaxPercentile: return r.cves.empty() ? QVariant{} : QVariant{r.max_percentile()};
                case ColRisk:      return r.cves.empty() ? QVariant{} : QVariant{QString::number(r.max_risk(), 'f', 2)};
                //Verified 열은 CVE가 없는 경우 빈 칸, CVE는 있지만 검증된 CVE가 없는 경우 "0/n", 검증된 CVE가 있는 경우 "✓ m/n" 형식으로 표시.
                case ColVerified: {
                    if (r.cves.empty()) return {};
                    const int verified = r.verified_cve_count();
                    const int total = static_cast<int>(r.cves.size());
                    return verified > 0
                        ? QString("%1 %2/%3").arg(QString::fromUtf8("\xe2\x9c\x93")).arg(verified).arg(total)
                        : QString("0/%1").arg(total);
                }
                case ColJa4s:      return QString::fromStdString(r.ja4s);
                case ColJa4x:      return QString::fromStdString(r.ja4x);
                case ColCdn:       return QString::fromStdString(r.cdn);
                case ColOs:        return QString::fromStdString(r.os_guess);
                default:           return {};
            }
        }

        // CVSS 컬럼의 UserRole 요청이 들어오면 r.max_cvss()를 반환. epss와 risk도 마찬가지.
        if (role == Qt::UserRole && index.column() == ColMaxCvss) {
            return r.max_cvss();
        }
        if (role == Qt::UserRole && index.column() == ColMaxEpss) {
            return r.max_epss();
        }
        if (role == Qt::UserRole && index.column() == ColMaxPercentile) {
            return r.max_percentile();
        }
        if (role == Qt::UserRole && index.column() == ColRisk) {
            return r.max_risk();
        }
        // Verified 컬럼의 UserRole 요청이 들어오면 r.has_verified_cve()를 반환.
        // 검증된 CVE가 하나라도 있으면 1, 없으면 0으로 반환해서 CvssDelegate에서 체크 표시 여부를 결정하는 데 사용.
        if (role == Qt::UserRole && index.column() == ColVerified) {
            return r.has_verified_cve() ? 1 : 0;
        }

        return {};
    }

//새로운 스캔 결과를 추가하는 함수.   
void ResultModel::appendResult(core::ScanResult result) {
        int row = static_cast<int>(results_.size());
        beginInsertRows({}, row, row);
        results_.push_back(std::move(result));
        endInsertRows();
    }

//스캔 전체 목록 한 번에 교체.
void ResultModel::setResults(std::vector<core::ScanResult> results) {
        beginResetModel();
        results_ = std::move(results);
        endResetModel();
    }

//특정 행의 ScanResult를 반환.
const core::ScanResult& ResultModel::resultAt(int row) const {
        return results_.at(row);
    }

//읽기 전용 참조로 전체 결과 목록 반환.
const std::vector<core::ScanResult>& ResultModel::allResults() const {
        return results_;
    }

//모델 초기화.
void ResultModel::clear() {
        beginResetModel();
        results_.clear();
        endResetModel();
    }

} 
