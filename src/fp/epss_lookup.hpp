#pragma once

// EPSS Lookup — CVE → Exploit Prediction Score.
//
// 근거 / 출처:
//   Jacobs et al., "Exploit Prediction Scoring System (EPSS)", arXiv 2102.03617 (2021)
//   Jacobs et al., "Enhancing Vulnerability Prioritization", arXiv 2302.14172 (2023)
//   FIRST.org EPSS 공식 — https://www.first.org/epss/
//   일일 CSV 피드 — https://epss.cyentia.com/epss_scores-current.csv.gz
//
// 입력 CSV 형식 (FIRST.org 공식):
//   #model_version:v2024.04.16,score_date:2024-04-29T00:00:00+0000
//   cve,epss,percentile
//   CVE-1999-0095,0.5436,0.97486
//   ...
//
// 본 클래스는 압축 안 된 .csv 만 지원 (gz 풀어서 입력).
//
// 의미:
//   - epss      : 향후 30일 내 야생에서 exploit 될 확률 (0..1).
//   - percentile: 전체 CVE 분포에서의 백분위 (0..1).
//   - CVSS × EPSS = "Risk Score" — 우선순위 정렬 권장 키.

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>

namespace sps::fp {

class EpssDb {
public:
    struct Entry {
        double epss = 0.0;
        double percentile = 0.0;
    };

    // 파일 경로에서 로드. 실패 → 빈 DB.
    static EpssDb load(const std::filesystem::path& csv_path);

    // CSV 본문 직접 파싱. 잘못된 라인은 스킵.
    static EpssDb parse(std::string_view csv_text);

    // CVE ID → (epss, percentile). 매칭 없으면 (0, 0).
    Entry lookup(std::string_view cve_id) const;

    bool empty() const noexcept { return map_.empty(); }
    std::size_t size() const noexcept { return map_.size(); }

private:
    std::unordered_map<std::string, Entry> map_;
};

} // namespace sps::fp
