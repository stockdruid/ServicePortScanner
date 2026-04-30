#pragma once

// Probe — 프로토콜별 서비스 식별 인터페이스.
//
// 규칙:
//  - identify() 는 예외를 던지지 않는다. 실패 → matched=false.
//  - 응답 누적은 8KB 까지만 (banner 보호).
//  - 코루틴 awaitable 반환.

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace sps::probes {

inline constexpr std::size_t kMaxBannerBytes = 8 * 1024;

struct ProbeOutcome {
    bool matched = false;
    std::string service;
    std::string version;
    std::string banner;
};

class Probe {
public:
    virtual ~Probe() = default;
    virtual std::string_view name() const noexcept = 0;

    // 후보 포트 — 빈 set 이면 모든 포트에서 시도.
    virtual std::vector<std::uint16_t> hint_ports() const { return {}; }

    virtual boost::asio::awaitable<ProbeOutcome>
    identify(boost::asio::ip::tcp::socket& sock,
             std::chrono::milliseconds io_timeout) = 0;
};

using ProbePtr = std::unique_ptr<Probe>;

// 표준 probe 모음 (등록 순서 = 시도 순서).
// probes_db_path 가 비어있지 않으면 외부 JSON DB 로드, 실패 시 임베디드 폴백.
// TLS probe 는 항상 네이티브로 끝에 추가.
std::vector<ProbePtr> default_probes(const std::string& probes_db_path = "");

} // namespace sps::probes
