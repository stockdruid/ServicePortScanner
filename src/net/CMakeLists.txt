# SPSCAN_BUILD_QT_BRIDGE 는 top-level CMakeLists 에서 정의.
# Qt-free 비동기 엔진 라이브러리 (CLI 만으로 동작 가능).
add_library(spscan_net STATIC
    async_pool.cpp
    rate_limiter.cpp
)

target_include_directories(spscan_net PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_net PUBLIC
    Boost::system
    spdlog::spdlog
    fmt::fmt
)

target_compile_features(spscan_net PUBLIC cxx_std_20)

# Qt bridge 는 GUI 빌드시에만 컴파일.
if(SPSCAN_BUILD_QT_BRIDGE)
    find_package(Qt6 CONFIG REQUIRED COMPONENTS Core)
    add_library(spscan_qt_bridge STATIC
        qt_bridge.cpp
    )
    set_target_properties(spscan_qt_bridge PROPERTIES AUTOMOC ON)
    target_include_directories(spscan_qt_bridge PUBLIC
        ${CMAKE_SOURCE_DIR}/src
    )
    target_link_libraries(spscan_qt_bridge PUBLIC
        spscan_net
        Qt6::Core
    )
    target_compile_features(spscan_qt_bridge PUBLIC cxx_std_20)
endif()
