find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# Stage 3: ssh/ftp/smtp/http 4종은 probe_engine 의 JSON 규칙으로 대체.
# TLS 만 OpenSSL 핸드셰이크 특수성으로 네이티브 유지.
add_library(spscan_probes STATIC
    banner_io.cpp
    probe_engine.cpp
    tls_probe.cpp
    registry.cpp
)

target_include_directories(spscan_probes PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_probes PUBLIC
    spscan_core
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

target_compile_features(spscan_probes PUBLIC cxx_std_20)
