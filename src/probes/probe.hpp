#pragma once

// Probe — 공통 결과 타입 + 상수.
//
// Stage 7: 가상 디스패치 (class Probe + unique_ptr<Probe>) 제거. 각 probe
// 는 std::variant<JsonProbe, TlsProbe> 의 한 alternative 로 직접 저장됨
// (probe_variant.hpp 참조). 디스패치는 std::visit + generic lambda — 컴파일
// 타임 dispatch, 인라인 가능, heap alloc 없음.
//
// 규칙:
//  - identify() 는 예외를 던지지 않는다. 실패 → matched=false.
//  - 응답 누적은 8KB 까지만 (banner 보호).
//  - 코루틴 awaitable 반환.

#include <cstddef>
#include <string>

namespace sps::probes {

inline constexpr std::size_t kMaxBannerBytes = 8 * 1024;

struct ProbeOutcome {
    bool matched = false;
    std::string service;
    std::string version;
    std::string banner;
    std::string ja4s;    // TLS probe 가 채움 (그 외 빈 문자열)
    std::string ja4x;    // TLS probe 가 채움 (그 외 빈 문자열)
};

} // namespace sps::probes
