#pragma once

// TLS 네이티브 probe — OpenSSL 핸드셰이크 + JA4S/JA4X 핑거프린트 캡처.
//
// Stage 7: 가상 base 제거, variant<JsonProbe, TlsProbe> 의 한 alternative
// 로 사용 (probe_variant.hpp). 상태 없는 클래스 — 매 identify() 호출마다
// SSL_CTX/SSL/BIO 을 로컬 RAII 로 생성·소멸.

#include "probes/probe.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

namespace sps::probes {

class TlsProbe {
public:
    std::string_view name() const noexcept { return "tls"; }

    std::vector<std::uint16_t> hint_ports() const {
        return {443, 8443, 465, 993, 995};
    }

    boost::asio::awaitable<ProbeOutcome>
    identify(boost::asio::ip::tcp::socket& sock,
             std::chrono::milliseconds timeout) const;
};

} // namespace sps::probes
