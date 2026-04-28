add_library(spscan_core STATIC
    scanner.cpp
)

target_include_directories(spscan_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_core PUBLIC
    Boost::system
    spdlog::spdlog
    fmt::fmt
)

target_compile_features(spscan_core PUBLIC cxx_std_20)
