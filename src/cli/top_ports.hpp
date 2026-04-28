#pragma once

// Nmap top-N 포트 (출현 빈도 기준).
//
// 출처: nmap-services TCP frequency 상위 100. nmap top-1000 의 핵심 부분.
// 사용법: --top-ports N (1..100). N>100 이면 100 으로 클램프.
//
// 참고: https://nmap.org/book/man-performance.html

#include <cstddef>
#include <cstdint>
#include <vector>

namespace sps::cli {

// 상위 n 개 포트 반환. n 이 임베드된 테이블 크기를 초과하면 전체 반환.
std::vector<std::uint16_t> top_n_ports(std::size_t n);

// 임베드된 테이블 크기.
std::size_t top_ports_table_size() noexcept;

} // namespace sps::cli
