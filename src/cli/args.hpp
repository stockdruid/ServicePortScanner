#pragma once

// CLI 인자 파싱 (CLI11 wrapping).
//
// 예: spscan --target 192.168.1.10 --ports 1-1024 --rate 200 --report json --out scan.json

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sps::cli {

enum class ReportKind { None, Json, Csv, Html };

struct Args {
    std::string target;                 // 단일 IP
    std::vector<std::uint16_t> ports;   // expanded port list
    double rate = 100.0;                // tokens/sec
    std::chrono::milliseconds timeout{2000};
    ReportKind report = ReportKind::None;
    std::string out_path;
    std::string cve_db_path;            // optional
    bool consent = false;               // --i-know-what-im-doing
    bool no_probe = false;              // skip service probes
    std::size_t threads = 0;            // 0 = hw_concurrency
};

struct ParseResult {
    bool ok = false;
    int exit_code = 0;        // CLI11 의 종료 코드 (--help 등)
    std::string error;        // ok=false 일 때 채움
    Args args;
};

ParseResult parse(int argc, char** argv);

// "1-1024,8080,8443" → [1..1024, 8080, 8443]. 잘못된 입력은 빈 리턴.
std::vector<std::uint16_t> expand_port_spec(std::string_view spec);

} // namespace sps::cli
