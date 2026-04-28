#pragma once

// Core Scanner — 단일 호스트:포트 TCP connect 스캔 코루틴.
//
// 설계:
//  - Qt 비의존 (core/ 규칙).
//  - 입력: host(IP/hostname), port, timeout.
//  - 출력: ScanResult. 예외 없음 — 실패는 PortState 로 표현.
//  - 호출자는 결과 socket 을 받아 Probe 로 후속 식별 가능 (run_with_socket).
//  - rate_limit 적용은 호출자 책임 (RateLimiter 를 전달).

#include "core/result.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
#include <cstdint>
#include <string>

namespace sps::core {

struct ScanRequest {
    std::string host;
    std::uint16_t port = 0;
    std::chrono::milliseconds timeout{2000};
};

// connect 만 시도. 후속 probe 없음.
// 호출자가 probe 를 수행하려면 별도로 재연결한다 (main.cpp 의 scan_one 참조).
boost::asio::awaitable<ScanResult>
connect_scan(boost::asio::any_io_executor exec, ScanRequest req);

} // namespace sps::core
