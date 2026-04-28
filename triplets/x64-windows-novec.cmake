# Custom triplet — VS 14.40 toolset 강제 + vectorized STL 비활성화.
# VS 17.14.x 의 STL 14.44 헤더와 libcpmt mismatch 우회.
# 모든 dep 가 14.40 STL 로 컴파일 → vectorized 심볼 emit 안 함.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PLATFORM_TOOLSET v143)
set(VCPKG_PLATFORM_TOOLSET_VERSION "14.40")
set(VCPKG_CXX_FLAGS "/D_DISABLE_VECTORIZED_ALGORITHMS")
set(VCPKG_C_FLAGS "/D_DISABLE_VECTORIZED_ALGORITHMS")
