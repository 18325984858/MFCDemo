cmake_minimum_required(VERSION 3.16)
project(ArkQt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 COMPONENTS Widgets Network QUIET)
if(NOT Qt6_FOUND)
    find_package(Qt5 5.15 COMPONENTS Widgets Network REQUIRED)
endif()

add_executable(ArkQt WIN32
    main.cpp
    MainWindow.cpp
    UdpLink.cpp
)

target_include_directories(ArkQt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../NetDrv)

target_link_libraries(ArkQt PRIVATE
    Qt::Widgets
    Qt::Network
)
