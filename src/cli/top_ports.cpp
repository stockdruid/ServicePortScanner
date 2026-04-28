#include "cli/top_ports.hpp"

#include <algorithm>

namespace sps::cli {

namespace {

// nmap-services TCP top-100 (frequency desc).
// 출처: https://github.com/nmap/nmap/blob/master/nmap-services 상위 100.
constexpr std::uint16_t kTopPorts[] = {
    80,    23,    443,   21,    22,    25,    3389,  110,   445,   139,
    143,   53,    135,   3306,  8080,  1723,  111,   995,   993,   5900,
    1025,  587,   8888,  199,   1720,  465,   548,   113,   81,    6001,
    10000, 514,   5060,  179,   1026,  2000,  8443,  8000,  32768, 554,
    26,    1433,  49152, 2001,  515,   8008,  49154, 1027,  5666,  646,
    5000,  5631,  631,   49153, 8081,  2049,  88,    79,    5800,  106,
    2121,  1110,  49155, 6000,  513,   990,   5357,  427,   49156, 543,
    544,   5101,  144,   7,     389,   8009,  3128,  444,   9999,  5009,
    7070,  5190,  3000,  5432,  1900,  3986,  13,    1029,  9,     5051,
    6646,  49157, 1028,  873,   1755,  2717,  4899,  9100,  119,   37,
};
constexpr std::size_t kTopPortsCount = sizeof(kTopPorts) / sizeof(kTopPorts[0]);

} // namespace

std::size_t top_ports_table_size() noexcept {
    return kTopPortsCount;
}

std::vector<std::uint16_t> top_n_ports(std::size_t n) {
    const std::size_t take = std::min(n, kTopPortsCount);
    return std::vector<std::uint16_t>(kTopPorts, kTopPorts + take);
}

} // namespace sps::cli
