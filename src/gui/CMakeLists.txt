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
    spscan_report
    Qt6::Widgets
    Qt6::Charts
)

target_compile_features(spscan_gui PRIVATE cxx_std_20)
