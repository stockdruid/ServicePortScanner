find_package(Catch2 3 CONFIG REQUIRED)

# Stage 0 — 효율성 개선 PR 의 before/after 측정 하네스.
# Catch2 v3 의 빌트인 micro-benchmark (BENCHMARK 매크로) 사용.
add_executable(spscan_bench
    bench_rate_limiter.cpp
    bench_scanner.cpp
    bench_top_ports.cpp
)

target_include_directories(spscan_bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(spscan_bench PRIVATE
    spscan_core
    spscan_net
    spscan_cli
    Catch2::Catch2WithMain
)

# CTest 등록 — `[bench]` 태그만, 라벨 "bench" 로 ctest -L bench 가능.
include(Catch)
catch_discover_tests(spscan_bench
    TEST_SPEC "[bench]"
    PROPERTIES LABELS "bench"
)
