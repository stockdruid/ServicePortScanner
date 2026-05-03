find_package(nlohmann_json CONFIG REQUIRED)

add_library(spscan_report STATIC
    writers.cpp
    csv_writer.cpp
    html_writer.cpp
    json_writer.cpp
)

target_include_directories(spscan_report PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_report PUBLIC
    spscan_core
    nlohmann_json::nlohmann_json
)

target_compile_features(spscan_report PUBLIC cxx_std_20)
