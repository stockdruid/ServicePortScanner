#include "probes/probe.hpp"

namespace sps::probes {

ProbePtr make_ssh_probe();
ProbePtr make_ftp_probe();
ProbePtr make_smtp_probe();
ProbePtr make_http_probe();
ProbePtr make_tls_probe();

std::vector<ProbePtr> default_probes() {
    std::vector<ProbePtr> v;
    v.push_back(make_ssh_probe());
    v.push_back(make_ftp_probe());
    v.push_back(make_smtp_probe());
    v.push_back(make_http_probe());
    v.push_back(make_tls_probe());
    return v;
}

} // namespace sps::probes
