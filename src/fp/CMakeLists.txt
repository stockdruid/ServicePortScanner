find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_library(spscan_fp STATIC
    ja4.cpp
    ja4_server.cpp
    ja4_x509.cpp
    cve_lookup.cpp
)

target_include_directories(spscan_fp PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_fp PUBLIC
    spscan_core
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

target_compile_features(spscan_fp PUBLIC cxx_std_20)
