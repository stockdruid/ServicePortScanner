find_package(CLI11 CONFIG REQUIRED)

add_library(spscan_cli STATIC
    args.cpp
    scope_guard.cpp
    top_ports.cpp
)

target_include_directories(spscan_cli PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_cli PUBLIC
    spscan_core
    Boost::system
    CLI11::CLI11
)

target_compile_features(spscan_cli PUBLIC cxx_std_20)
