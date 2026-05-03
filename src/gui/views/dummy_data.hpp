#pragma once
// tests/dummy_data.hpp -> GUI prototype demo data

#include "core/result.hpp"
#include <vector>

namespace sps::test {

inline std::vector<core::ScanResult> make_dummy_results() {
    using namespace core;
    std::vector<ScanResult> results;

    // 1. Required SSH probe.
    {
        ScanResult r;
        r.target_host = "192.168.122.11";
        r.resolved_ip = "192.168.122.11";
        r.port        = 22;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(3);
        r.os_guess    = "Linux 5.15";

        r.service.name       = "ssh";
        r.service.product    = "OpenSSH";
        r.service.version    = "8.2";
        r.service.extra_info = "Ubuntu 20.04";
        r.service.banner_raw = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9";

        CveInfo cve;
        cve.cve_id      = "CVE-2020-15778";
        cve.description = "OpenSSH scp client command injection risk";
        cve.cvss_score  = 7.8f;
        cve.severity    = Severity::High;
        cve.epss        = 0.18;
        cve.percentile  = 0.86;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 2. Required FTP probe.
    {
        ScanResult r;
        r.target_host = "192.168.122.12";
        r.resolved_ip = "192.168.122.12";
        r.port        = 21;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(5);
        r.os_guess    = "Linux 4.19";

        r.service.name       = "ftp";
        r.service.product    = "vsftpd";
        r.service.version    = "3.0.3";
        r.service.extra_info = "anonymous disabled";
        r.service.banner_raw = "220 (vsFTPd 3.0.3)";

        CveInfo cve;
        cve.cve_id      = "CVE-2021-3618";
        cve.description = "FTP service configuration exposure scenario";
        cve.cvss_score  = 5.3f;
        cve.severity    = Severity::Medium;
        cve.epss        = 0.08;
        cve.percentile  = 0.66;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 3. Required SMTP probe.
    {
        ScanResult r;
        r.target_host = "192.168.122.13";
        r.resolved_ip = "192.168.122.13";
        r.port        = 25;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(4);
        r.os_guess    = "Linux 5.4";

        r.service.name       = "smtp";
        r.service.product    = "Postfix";
        r.service.version    = "3.3.0";
        r.service.extra_info = "Ubuntu 18.04";
        r.service.banner_raw = "220 mail.local ESMTP Postfix";

        CveInfo cve;
        cve.cve_id      = "CVE-2019-3462";
        cve.description = "SMTP relay exposure scenario";
        cve.cvss_score  = 3.7f;
        cve.severity    = Severity::Low;
        cve.epss        = 0.03;
        cve.percentile  = 0.42;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 4. Required HTTP probe. This is the highest-risk demo row.
    {
        ScanResult r;
        r.target_host = "192.168.122.14";
        r.resolved_ip = "192.168.122.14";
        r.port        = 80;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(2);
        r.cdn         = "cloudflare";
        r.os_guess    = "Linux 5.10";

        r.service.name       = "http";
        r.service.product    = "Apache httpd";
        r.service.version    = "2.4.49";
        r.service.extra_info = "Debian";
        r.service.banner_raw = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49";

        CveInfo cve;
        cve.cve_id          = "CVE-2021-41773";
        cve.description     = "Apache path traversal and remote code execution";
        cve.cvss_score      = 9.8f;
        cve.severity        = Severity::Critical;
        cve.epss            = 0.92;
        cve.percentile      = 0.99;
        cve.nuclei_verified = true;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 5. Required TLS probe.
    {
        ScanResult r;
        r.target_host = "192.168.122.15";
        r.resolved_ip = "192.168.122.15";
        r.port        = 443;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(4);
        r.ja4s        = "t13d3112h2_e8f1e7e78f70_6bebaf5329ac";
        r.ja4x        = "a1b2c3d4e5f6a7b8_c32a5380a08cec8d_4f48e4e00304ed25";
        r.cdn         = "akamai";
        r.os_guess    = "Linux 6.1";

        r.service.name       = "tls";
        r.service.product    = "nginx";
        r.service.version    = "1.18.0";
        r.service.extra_info = "Ubuntu TLS endpoint";
        r.service.banner_raw = "TLS ServerHello; HTTP/1.1 200 OK\r\nServer: nginx/1.18.0";

        CveInfo cve;
        cve.cve_id      = "CVE-2021-23017";
        cve.description = "nginx resolver off-by-one write";
        cve.cvss_score  = 9.4f;
        cve.severity    = Severity::Critical;
        cve.epss        = 0.04;
        cve.percentile  = 0.55;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 6. Extra HTTP probe sample.
    {
        ScanResult r;
        r.target_host = "192.168.122.16";
        r.resolved_ip = "192.168.122.16";
        r.port        = 8080;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(6);
        r.os_guess    = "Linux 5.10";

        r.service.name       = "http";
        r.service.product    = "Jetty";
        r.service.version    = "9.4.43";
        r.service.extra_info = "admin console exposed";
        r.service.banner_raw = "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.43)";

        CveInfo cve;
        cve.cve_id      = "CVE-2021-28164";
        cve.description = "Jetty HTTP request smuggling vulnerability";
        cve.cvss_score  = 5.9f;
        cve.severity    = Severity::Medium;
        cve.epss        = 0.14;
        cve.percentile  = 0.80;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 7. Extra TLS probe sample.
    {
        ScanResult r;
        r.target_host = "192.168.122.17";
        r.resolved_ip = "192.168.122.17";
        r.port        = 8443;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(7);
        r.ja4s        = "t12d1516h2_8daaf6152771_02713d6af862";
        r.ja4x        = "7b3d9f1a1e25e7f0_7f3d1a8364b8_1ef2ab641922";
        r.os_guess    = "Linux 5.15";

        r.service.name       = "tls";
        r.service.product    = "Tomcat";
        r.service.version    = "9.0.45";
        r.service.extra_info = "manager app reachable over TLS";
        r.service.banner_raw = "TLS ServerHello; HTTP/1.1 401 Unauthorized\r\nServer: Apache-Coyote/1.1";

        CveInfo cve;
        cve.cve_id          = "CVE-2020-1938";
        cve.description     = "Apache Tomcat AJP file read/include vulnerability";
        cve.cvss_score      = 9.8f;
        cve.severity        = Severity::Critical;
        cve.epss            = 0.33;
        cve.percentile      = 0.91;
        cve.nuclei_verified = true;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 8. Extra SSH probe sample.
    {
        ScanResult r;
        r.target_host = "192.168.122.18";
        r.resolved_ip = "192.168.122.18";
        r.port        = 2222;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(8);
        r.os_guess    = "Linux 4.14";

        r.service.name       = "ssh";
        r.service.product    = "Dropbear SSH";
        r.service.version    = "2018.76";
        r.service.extra_info = "embedded device";
        r.service.banner_raw = "SSH-2.0-dropbear_2018.76";

        CveInfo cve;
        cve.cve_id      = "CVE-2018-15599";
        cve.description = "Dropbear username enumeration scenario";
        cve.cvss_score  = 5.3f;
        cve.severity    = Severity::Medium;
        cve.epss        = 0.06;
        cve.percentile  = 0.61;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 9. Extra FTP probe sample.
    {
        ScanResult r;
        r.target_host = "192.168.122.19";
        r.resolved_ip = "192.168.122.19";
        r.port        = 2121;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(6);
        r.os_guess    = "Linux 5.4";

        r.service.name       = "ftp";
        r.service.product    = "ProFTPD";
        r.service.version    = "1.3.5";
        r.service.extra_info = "legacy upload endpoint";
        r.service.banner_raw = "220 ProFTPD 1.3.5 Server";

        CveInfo cve;
        cve.cve_id      = "CVE-2015-3306";
        cve.description = "ProFTPD mod_copy arbitrary file copy vulnerability";
        cve.cvss_score  = 6.5f;
        cve.severity    = Severity::Medium;
        cve.epss        = 0.22;
        cve.percentile  = 0.88;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    // 10. Non-required service diversity sample: keep Redis only.
    {
        ScanResult r;
        r.target_host = "192.168.122.20";
        r.resolved_ip = "192.168.122.20";
        r.port        = 6379;
        r.protocol    = "tcp";
        r.state       = PortState::Open;
        r.rtt         = std::chrono::milliseconds(1);
        r.os_guess    = "Linux 5.4";

        r.service.name       = "redis";
        r.service.product    = "Redis";
        r.service.version    = "6.0.16";
        r.service.extra_info = "Linux 5.4.0, no auth";
        r.service.banner_raw = "# Server\r\nredis_version:6.0.16\r\nos:Linux 5.4.0";

        CveInfo cve;
        cve.cve_id          = "CVE-2022-0543";
        cve.description     = "Redis Lua sandbox escape leading to remote code execution";
        cve.cvss_score      = 10.0f;
        cve.severity        = Severity::Critical;
        cve.epss            = 0.41;
        cve.percentile      = 0.93;
        cve.nuclei_verified = true;
        r.cves.push_back(cve);

        results.push_back(r);
    }

    return results;
}

} // namespace sps::test
