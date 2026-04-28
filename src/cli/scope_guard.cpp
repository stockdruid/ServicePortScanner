#include "cli/scope_guard.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

namespace sps::cli {

namespace {

namespace ip = boost::asio::ip;

bool is_private_v4(const ip::address_v4& a) {
    if (a.is_loopback() || a.is_unspecified()) return true;
    const auto bytes = a.to_bytes();
    if (bytes[0] == 10) return true;                                   // 10/8
    if (bytes[0] == 192 && bytes[1] == 168) return true;               // 192.168/16
    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true; // 172.16/12
    if (bytes[0] == 169 && bytes[1] == 254) return true;               // link-local
    return false;
}

bool is_private_v6(const ip::address_v6& a) {
    if (a.is_loopback() || a.is_unspecified()) return true;
    if (a.is_link_local() || a.is_site_local()) return true;
    // ULA fc00::/7
    const auto bytes = a.to_bytes();
    return (bytes[0] & 0xfe) == 0xfc;
}

} // namespace

ScopeDecision check_scope(std::string_view target_ip, ScopeOptions opts) {
    boost::system::error_code ec;
    auto addr = ip::make_address(std::string(target_ip), ec);
    if (ec) return ScopeDecision::DeniedInvalidAddress;

    const bool internal = addr.is_v4()
        ? is_private_v4(addr.to_v4())
        : is_private_v6(addr.to_v6());

    if (internal) return ScopeDecision::Allowed;
    if (opts.explicit_consent) return ScopeDecision::Allowed;
    return ScopeDecision::DeniedExternalNeedsConsent;
}

std::string_view describe(ScopeDecision d) noexcept {
    switch (d) {
        case ScopeDecision::Allowed: return "allowed";
        case ScopeDecision::DeniedExternalNeedsConsent:
            return "external IP — pass --i-know-what-im-doing to proceed";
        case ScopeDecision::DeniedInvalidAddress:
            return "invalid address";
    }
    return "unknown";
}

} // namespace sps::cli
