find_package(Catch2 3 CONFIG REQUIRED)
find_package(Qt6 CONFIG REQUIRED COMPONENTS Core Test)

# --- 비-Qt 테스트 (Catch2 기본 main) ---
add_executable(net_tests
    rate_limiter_test.cpp
    async_pool_test.cpp
)
target_link_libraries(net_tests PRIVATE
    spscan_net
    Catch2::Catch2WithMain
)

# --- Qt 테스트 (자체 main 으로 QCoreApplication 주입) ---
add_executable(net_qt_tests
    qt_test_main.cpp
    qt_bridge_test.cpp
)
set_target_properties(net_qt_tests PROPERTIES AUTOMOC ON)
target_link_libraries(net_qt_tests PRIVATE
    spscan_net
    Catch2::Catch2
    Qt6::Core
    Qt6::Test
)

include(Catch)
catch_discover_tests(net_tests)
catch_discover_tests(net_qt_tests)
