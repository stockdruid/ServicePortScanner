#pragma once

// Scope Guard — 스캔 대상 IP 가 허용 범위에 있는지 검증.
//
// 기본 허용:
//  - loopback (127.0.0.0/8, ::1)
//  - RFC1918 (10/8, 172.16/12, 192.168/16)
//  - link-local (169.254/16)
// 외부 IP 는 explicit_consent=true 일 때만 허용.

#include <string>
#include <string_view>

namespace sps::cli {

enum class ScopeDecision {
    Allowed,
    DeniedExternalNeedsConsent,
    DeniedInvalidAddress,
};

struct ScopeOptions {
    bool explicit_consent = false;
};

ScopeDecision check_scope(std::string_view target_ip, ScopeOptions opts);

std::string_view describe(ScopeDecision d) noexcept;

} // namespace sps::cli
