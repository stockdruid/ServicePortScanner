#include "probes/probe.hpp"
#include "probes/probe_engine.hpp"

namespace sps::probes {

ProbePtr make_tls_probe();

std::vector<ProbePtr> default_probes(const std::string& probes_db_path) {
    auto db = probes_db_path.empty()
        ? ProbeDatabase::load_default()
        : ProbeDatabase::load_from_file(probes_db_path);
    if (db.empty()) {
        // 외부 파일 실패 → 임베디드 폴백.
        db = ProbeDatabase::load_default();
    }
    auto v = probes_from_database(db);
    v.push_back(make_tls_probe());
    return v;
}

} // namespace sps::probes
