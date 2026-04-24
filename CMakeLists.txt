cmake_minimum_required(VERSION 3.25)
project(service-port-scanner CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
endif()

# 모듈은 각 팀원 브랜치에서 add_subdirectory 로 추가.
