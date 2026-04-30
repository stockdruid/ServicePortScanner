find_package(Catch2 3 CONFIG REQUIRED)

# --- 비-Qt 테스트 (Catch2 기본 main) ---
add_executable(net_tests
    rate_limiter_test.cpp
    async_pool_test.cpp
)
target_link_libraries(net_tests PRIVATE
    spscan_net
    Catch2::Catch2WithMain
)

add_executable(core_tests
    scanner_test.cpp
)
target_link_libraries(core_tests PRIVATE
    spscan_core
    Catch2::Catch2WithMain
)

add_executable(cli_tests
    args_test.cpp
    scope_guard_test.cpp
)
target_link_libraries(cli_tests PRIVATE
    spscan_cli
    Catch2::Catch2WithMain
)

add_executable(fp_tests
    cve_lookup_test.cpp
    ja4_test.cpp
    ja4_server_test.cpp
    ja4_x509_test.cpp
    cdn_lookup_test.cpp
)
target_link_libraries(fp_tests PRIVATE
    spscan_fp
    Catch2::Catch2WithMain
)

add_executable(report_tests
    report_test.cpp
)
target_link_libraries(report_tests PRIVATE
    spscan_report
    Catch2::Catch2WithMain
)

add_executable(probes_tests
    probe_engine_test.cpp
)
target_link_libraries(probes_tests PRIVATE
    spscan_probes
    Catch2::Catch2WithMain
)

# --- Qt 테스트 (옵션, qt_bridge 빌드 시에만) ---
if(SPSCAN_BUILD_QT_BRIDGE)
    find_package(Qt6 CONFIG REQUIRED COMPONENTS Core Test)
    add_executable(net_qt_tests
        qt_test_main.cpp
        qt_bridge_test.cpp
    )
    set_target_properties(net_qt_tests PROPERTIES AUTOMOC ON)
    target_link_libraries(net_qt_tests PRIVATE
        spscan_qt_bridge
        Catch2::Catch2
        Qt6::Core
        Qt6::Test
    )
endif()

include(Catch)
catch_discover_tests(net_tests)
catch_discover_tests(core_tests)
catch_discover_tests(cli_tests)
catch_discover_tests(fp_tests)
catch_discover_tests(report_tests)
catch_discover_tests(probes_tests)
if(SPSCAN_BUILD_QT_BRIDGE)
    catch_discover_tests(net_qt_tests)
endif()

# Stage 0 — 효율성 PR before/after 측정용 micro-benchmark.
if(SPSCAN_BUILD_BENCH)
    add_subdirectory(bench)
endif()
