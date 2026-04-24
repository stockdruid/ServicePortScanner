cmake_minimum_required(VERSION 3.25)
project(service-port-scanner CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Qt6 자동 MOC/RCC/UIC
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
endif()

find_package(Boost  CONFIG REQUIRED COMPONENTS system)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt    CONFIG REQUIRED)
find_package(Qt6    CONFIG REQUIRED COMPONENTS Core)

add_subdirectory(src/net)

enable_testing()
add_subdirectory(tests)
