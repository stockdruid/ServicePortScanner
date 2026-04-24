add_library(spscan_net STATIC
    async_pool.cpp
    rate_limiter.cpp
    qt_bridge.cpp
)

# AUTOMOC 가 헤더(qt_bridge.hpp) 의 Q_OBJECT 감지해서 moc 자동 실행.
set_target_properties(spscan_net PROPERTIES AUTOMOC ON)

target_include_directories(spscan_net PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_net PUBLIC
    Boost::system
    spdlog::spdlog
    fmt::fmt
    Qt6::Core
)

target_compile_features(spscan_net PUBLIC cxx_std_20)
