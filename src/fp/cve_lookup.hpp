#pragma once

// CVE Lookup — service+version → 알려진 CVE 매칭.
//
// 데이터: data/nvd_min.json (사전 가공된 최소 NVD 추출본).
// 형식:
//   {
//     "openssh": [
//       { "version_prefix": "7.4",   "id": "CVE-2018-15473", "cvss": 5.3 },
//       ...
//     ],
//     "vsftpd": [ { ... } ]
//   }

#include "core/result.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace sps::fp {

class CveDb {
public:
    // 빈 파일 경로 → 비어있는 DB. 파싱 실패 → 비어있는 DB (errors 로 보고).
    static CveDb load(const std::filesystem::path& json_path);
    static CveDb load_from_string(std::string_view json_text);

    // 빈 결과 = 매칭 없음.
    std::vector<sps::core::CveHit>
    lookup(std::string_view service, std::string_view version) const;

    bool empty() const noexcept { return entries_.empty(); }
    std::size_t size() const noexcept { return entries_.size(); }

private:
    struct Entry {
        std::string service_lower;
        std::string version_prefix;
        std::string id;
        double cvss = 0.0;
    };
    std::vector<Entry> entries_;
};

} // namespace sps::fp
