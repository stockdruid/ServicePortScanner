cmake_minimum_required(VERSION 3.25)
project(service-port-scanner CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SPSCAN_BUILD_GUI "Build Qt6 GUI front-end" OFF)
option(SPSCAN_BUILD_QT_BRIDGE "Build Qt signal bridge library" ${SPSCAN_BUILD_GUI})
option(SPSCAN_BUILD_TESTS "Build tests" ON)

# Qt6 자동 MOC/RCC/UIC (GUI 또는 qt_bridge 빌드 시).
if(SPSCAN_BUILD_GUI OR SPSCAN_BUILD_QT_BRIDGE)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
endif()

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
endif()

# Boost.Asio 가 Windows 타깃을 알 수 있도록.
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# MSVC STL vectorized 심볼 ABI mismatch 우회 (VS 17.14.x 일시 회피).
if(MSVC)
    add_compile_definitions(_DISABLE_VECTORIZED_ALGORITHMS)
endif()

find_package(Boost  CONFIG REQUIRED COMPONENTS system)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt    CONFIG REQUIRED)

add_subdirectory(src/core)
add_subdirectory(src/net)
add_subdirectory(src/fp)
add_subdirectory(src/probes)
add_subdirectory(src/cli)
add_subdirectory(src/report)

# Top-level CLI executable.
find_package(CLI11 CONFIG REQUIRED)
add_executable(spscan src/main.cpp)
target_link_libraries(spscan PRIVATE
    spscan_core
    spscan_net
    spscan_probes
    spscan_fp
    spscan_cli
    spscan_report
)

if(SPSCAN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
