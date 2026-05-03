add_library(spscan_scan STATIC
    scan_pipeline.cpp
)

target_include_directories(spscan_scan PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_scan PUBLIC
    spscan_core
    spscan_net
    spscan_probes
    spscan_fp
    Boost::system
)

target_compile_features(spscan_scan PUBLIC cxx_std_20)
