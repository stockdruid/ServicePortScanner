#pragma once

// ProbeVariant — JsonProbe + TlsProbe 의 type-safe union.
//
// Stage 7: 가상 디스패치 (Probe* + virtual identify) 를 std::variant +
// std::visit 정적 디스패치로 교체. 결과:
//  - heap alloc 없음 (이전엔 unique_ptr<Probe> 마다 1회)
//  - 가상 호출 없음 (compiler 가 visit 의 generic lambda 인라인 가능)
//  - 캐시 친화적 (probes 벡터가 contiguous storage)
//
// 사용:
//  for (auto& probe : probes) {
//      auto result = co_await std::visit(
//          [&](auto& p) -> awaitable<ProbeOutcome> {
//              return p.identify(sock, timeout);
//          }, probe);
//      ...
//  }

#include "probes/probe_engine.hpp"
#include "probes/tls_probe.hpp"

#include <string>
#include <variant>
#include <vector>

namespace sps::probes {

using ProbeVariant = std::variant<JsonProbe, TlsProbe>;

// 임베디드 또는 외부 JSON probe DB 로드 + TLS native probe 추가.
// 호출 결과: [JsonProbe(ssh), JsonProbe(ftp), ..., TlsProbe()]
std::vector<ProbeVariant> default_probes(const std::string& probes_db_path = "");

} // namespace sps::probes
