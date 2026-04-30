// Stage 3 — ProbeDatabase 파서/규칙 검증.

#include "probes/probe_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <fstream>
#include <regex>
#include <string>

using sps::probes::ProbeDatabase;
using sps::probes::ProbeRule;

TEST_CASE("ProbeDatabase loads embedded default", "[probe_engine]") {
    auto db = ProbeDatabase::load_default();
    REQUIRE(db.size() == 4);

    bool has_ssh = false, has_ftp = false, has_smtp = false, has_http = false;
    for (const auto& r : db.rules()) {
        if (r.name == "ssh")  has_ssh  = true;
        if (r.name == "ftp")  has_ftp  = true;
        if (r.name == "smtp") has_smtp = true;
        if (r.name == "http") has_http = true;
    }
    REQUIRE(has_ssh);
    REQUIRE(has_ftp);
    REQUIRE(has_smtp);
    REQUIRE(has_http);
}

TEST_CASE("ProbeDatabase parses minimal valid JSON", "[probe_engine]") {
    constexpr const char* json = R"({
        "version": 1,
        "probes": [
            { "name": "echo", "ports": [7],
              "match": [ { "regex": "^hello", "service": "echo" } ] }
        ]
    })";
    auto db = ProbeDatabase::parse(json);
    REQUIRE(db.size() == 1);

    const auto& r = db.rules().front();
    REQUIRE(r.name == "echo");
    REQUIRE(r.ports.size() == 1);
    REQUIRE(r.ports.front() == 7);
    REQUIRE(r.matches.size() == 1);
    REQUIRE(r.send_payload.empty());
}

TEST_CASE("ProbeDatabase skips entries with invalid regex", "[probe_engine]") {
    constexpr const char* json = R"({
        "version": 1,
        "probes": [
            { "name": "bad", "match": [ { "regex": "[unclosed" } ] }
        ]
    })";
    auto db = ProbeDatabase::parse(json);
    REQUIRE(db.empty());
}

TEST_CASE("ProbeDatabase rejects malformed JSON", "[probe_engine]") {
    auto db = ProbeDatabase::parse("not json at all {{{");
    REQUIRE(db.empty());
}

TEST_CASE("Default SSH regex matches OpenSSH banner", "[probe_engine]") {
    auto db = ProbeDatabase::load_default();
    const ProbeRule* ssh = nullptr;
    for (const auto& r : db.rules()) {
        if (r.name == "ssh") { ssh = &r; break; }
    }
    REQUIRE(ssh != nullptr);
    REQUIRE(ssh->matches.size() >= 1);

    const std::string banner = "SSH-2.0-OpenSSH_8.4p1 Debian\r\n";
    std::smatch m;
    REQUIRE(std::regex_search(banner, m, ssh->matches.front().re));
    REQUIRE(m.size() >= 2);
    REQUIRE(m[1].str().find("OpenSSH_8.4p1") != std::string::npos);
}

TEST_CASE("Default HTTP regex captures Server header", "[probe_engine]") {
    auto db = ProbeDatabase::load_default();
    const ProbeRule* http = nullptr;
    for (const auto& r : db.rules()) {
        if (r.name == "http") { http = &r; break; }
    }
    REQUIRE(http != nullptr);
    REQUIRE_FALSE(http->send_payload.empty());

    const std::string banner =
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.18.0\r\n"
        "Content-Length: 0\r\n\r\n";
    std::smatch m;
    REQUIRE(std::regex_search(banner, m, http->matches.front().re));
    REQUIRE(m.size() >= 2);
    REQUIRE(m[1].str().find("nginx/1.18.0") != std::string::npos);
}

TEST_CASE("Default FTP regex matches vsFTPd banner", "[probe_engine]") {
    auto db = ProbeDatabase::load_default();
    const ProbeRule* ftp = nullptr;
    for (const auto& r : db.rules()) {
        if (r.name == "ftp") { ftp = &r; break; }
    }
    REQUIRE(ftp != nullptr);

    const std::string banner = "220 (vsFTPd 3.0.3)\r\n";
    std::smatch m;
    REQUIRE(std::regex_search(banner, m, ftp->matches.front().re));
    REQUIRE(m.size() >= 2);
    REQUIRE(m[1].str().find("vsFTPd") != std::string::npos);
}

TEST_CASE("ProbeDatabase loads from file (round-trip)",
          "[probe_engine]") {
    // 현재 디렉토리에 임시 파일 — 테스트 종료 시 삭제.
    const std::string path = "spscan_probe_engine_test_db.json";
    {
        std::ofstream f(path);
        f << R"({"version":1,"probes":[{"name":"x","ports":[9],
            "match":[{"regex":"^X","service":"x"}]}]})";
    }
    auto db = ProbeDatabase::load_from_file(path);
    std::remove(path.c_str());

    REQUIRE(db.size() == 1);
    REQUIRE(db.rules().front().name == "x");
}

TEST_CASE("ProbeDatabase missing file returns empty", "[probe_engine]") {
    auto db = ProbeDatabase::load_from_file("/nonexistent/_path_/probes.json");
    REQUIRE(db.empty());
}
