#pragma once

// CDN/WAF 제공자 식별 — Stage 5.
//
// 입력: 스캔 대상 IPv4 주소 (dotted decimal).
// 출력: 매칭된 provider 문자열 ("cloudflare", "fastly" 등) 또는 빈 문자열.
//
// 데이터: data/cdn_ranges.json (또는 임베디드 기본 DB).
//   {
//     "version": 1,
//     "ranges": [
//       { "cidr": "104.16.0.0/13", "provider": "cloudflare" },
//       ...
//     ]
//   }
//
// 한계 (MVP):
//   - IPv4 CIDR 만. IPv6 는 후속.
//   - 정적 prefix 만. ASN-기반 매칭 (Akamai 대다수) 은 별도 데이터 필요.
//   - 발표 자료 시점 고정 — 정기 갱신 필요.
//
// 참고: https://www.cloudflare.com/ips/ , https://api.fastly.com/public-ip-list

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sps::fp {

class CdnDatabase {
public:
    // 임베디드 기본 DB (Cloudflare/Fastly/AWS CloudFront/Imperva 일부).
    static CdnDatabase load_default();

    // 외부 JSON 파일에서 로드. 실패 → 빈 DB.
    static CdnDatabase load_from_file(const std::string& path);

    // JSON 문자열 직접 파싱. 잘못된 항목은 스킵.
    static CdnDatabase parse(std::string_view json_text);

    // 매칭된 첫 provider 반환, 없으면 빈 문자열.
    std::string lookup(std::string_view ipv4) const;

    std::size_t size() const noexcept { return ranges_.size(); }
    bool empty() const noexcept { return ranges_.empty(); }

private:
    struct Range {
        std::uint32_t base = 0;
        std::uint32_t mask = 0;
        std::string provider;
    };
    std::vector<Range> ranges_;
};

} // namespace sps::fp
