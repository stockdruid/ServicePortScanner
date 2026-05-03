#pragma once

// scan_pipeline — 한 포트당 스캔 파이프라인 (rate-limit → connect →
// probe → CVE lookup) 의 단일 정본.
//
// 이전엔 src/main.cpp (CLI) 와 src/gui/views/scan_controller.cpp (GUI)
// 에 동일한 scan_one 함수가 70줄씩 중복돼 있었음. 한 곳에서 정의,
// 양쪽에서 호출.

#include "core/result.hpp"
#include "fp/cve_lookup.hpp"
#include "net/rate_limiter.hpp"
#include "probes/probe_variant.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace sps::scan {

// 한 포트 처리: rate-limit → connect → (optional) probe → CVE lookup.
//  - probes / cves 가 nullptr 또는 empty 면 해당 단계 스킵.
//  - state != Open 이면 probe / CVE 단계 즉시 스킵.
//  - probe 디스패치는 std::visit (Stage 7).
boost::asio::awaitable<sps::core::ScanResult>
scan_one(boost::asio::any_io_executor exec,
         std::string host,
         std::uint16_t port,
         std::chrono::milliseconds timeout,
         sps::net::RateLimiter& limiter,
         const std::vector<sps::probes::ProbeVariant>* probes,
         const sps::fp::CveDb* cves);

} // namespace sps::scan
