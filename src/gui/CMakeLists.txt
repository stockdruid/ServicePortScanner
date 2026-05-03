# GUI 빌드는 SPSCAN_BUILD_GUI=ON 일 때만 활성화. (top-level CMakeLists.txt 에서 분기)
# AUTOMOC/AUTORCC/AUTOUIC 도 top-level 에서 켜져 있어야 .ui 와 Q_OBJECT 매크로 처리됨.

find_package(Qt6 CONFIG REQUIRED COMPONENTS Widgets Charts)

add_executable(spscan_gui
    main.cpp
    views/main_window.hpp
    views/main_window.cpp
    views/main_window.ui
    views/result_model.hpp
    views/result_model.cpp
    views/details_panel.hpp
    views/details_panel.cpp
    views/details_panel.ui
    views/charts_panel.hpp
    views/charts_panel.cpp
    views/cvss_delegate.hpp
    views/cvss_delegate.cpp
    views/epss_delegate.hpp
    views/epss_delegate.cpp
    views/risk_delegate.hpp
    views/risk_delegate.cpp
    views/export_actions.hpp
    views/export_actions.cpp
    views/scan_controller.hpp
    views/scan_controller.cpp
    views/dummy_data.hpp
)

set_target_properties(spscan_gui PROPERTIES
    AUTOMOC ON
    AUTORCC ON
    AUTOUIC ON
    WIN32_EXECUTABLE ON   # Windows: 콘솔 창 없이 GUI 실행
)

target_include_directories(spscan_gui PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(spscan_gui PRIVATE
    spscan_core
    spscan_net
    spscan_qt_bridge
    spscan_probes
    spscan_fp
    spscan_report
    Qt6::Widgets
    Qt6::Charts
)

target_compile_features(spscan_gui PRIVATE cxx_std_20)

# Windows: windeployqt 가 빌드 후 Qt DLL/플러그인을 .exe 옆에 자동 복사.
# 안 그러면 "no Qt platform plugin" 오류로 실행 불가.
if(WIN32)
    # vcpkg 가 설치한 windeployqt 위치(tools/Qt6/bin/) 또는 Qt 공식 인스톨러 bin/.
    get_target_property(_qmake_exec Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(_qt_bin_dir "${_qmake_exec}" DIRECTORY)
    find_program(WINDEPLOYQT_EXE windeployqt
        HINTS "${_qt_bin_dir}"
              "${_qt_bin_dir}/../../../tools/Qt6/bin"
        REQUIRED)
    add_custom_command(TARGET spscan_gui POST_BUILD
        COMMAND "${WINDEPLOYQT_EXE}"
                --release
                --no-translations
                --no-system-d3d-compiler
                --no-opengl-sw
                "$<TARGET_FILE:spscan_gui>"
        COMMENT "Running windeployqt to bundle Qt DLLs + platform plugins"
        VERBATIM)
endif()
