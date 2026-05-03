#include "probes/probe_variant.hpp"

#include <utility>

namespace sps::probes {

std::vector<ProbeVariant> default_probes(const std::string& probes_db_path) {
    auto db = probes_db_path.empty()
        ? ProbeDatabase::load_default()
        : ProbeDatabase::load_from_file(probes_db_path);
    if (db.empty()) {
        // 외부 파일 실패 → 임베디드 폴백.
        db = ProbeDatabase::load_default();
    }
    auto json_probes = json_probes_from_database(db);

    std::vector<ProbeVariant> out;
    out.reserve(json_probes.size() + 1);
    for (auto& jp : json_probes) {
        out.emplace_back(std::move(jp));
    }
    out.emplace_back(TlsProbe{});  // 항상 끝에 TLS native probe.
    return out;
}

} // namespace sps::probes
