cmake_minimum_required(VERSION 3.10)

project(embedded_linux_nids)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

pkg_check_modules(PCAP REQUIRED libpcap)

find_package(SQLite3 REQUIRED)

include_directories(
    ${PCAP_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
    include
)

link_directories(
    ${PCAP_LIBRARY_DIRS}
)
add_executable(nids
    src/main.cpp
    src/packet_monitor.cpp
    src/connection_tracker.cpp
    src/detector.cpp
    src/database.cpp
    src/firewall_manager.cpp
    src/config_manager.cpp
    src/risk_engine.cpp
)
target_link_libraries(

    nids

    ${PCAP_LIBRARIES}

    SQLite::SQLite3
)
