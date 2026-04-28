find_package(OpenSSL REQUIRED)

add_library(spscan_probes STATIC
    banner_io.cpp
    ssh_probe.cpp
    ftp_probe.cpp
    smtp_probe.cpp
    http_probe.cpp
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
)

target_compile_features(spscan_probes PUBLIC cxx_std_20)
