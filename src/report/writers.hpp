#pragma once

// 결과 직렬화기 — 동일한 ScanResult 벡터를 여러 포맷으로 출력.
// MVP: JSON, CSV, HTML.

#include "core/result.hpp"

#include <span>
#include <string>

namespace sps::report {

std::string to_json(std::span<const sps::core::ScanResult> results);
std::string to_csv(std::span<const sps::core::ScanResult> results);
std::string to_html(std::span<const sps::core::ScanResult> results);

// path 가 비면 stdout 으로. 실패 시 false.
bool write_to_file(const std::string& path, const std::string& content);

} // namespace sps::report
