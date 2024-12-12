cmake_minimum_required(VERSION 3.9)

project(ecb-slave-c-server)

add_compile_definitions(SAFE_C_LOG_EN__DBG=1)
add_compile_definitions(SAFE_C_LOG_EN__INF=1)
add_compile_definitions(SAFE_C_LOG_EN__WRN=1)
add_compile_definitions(SAFE_C_LOG_EN__ERR=1)
add_compile_definitions(ECBS_DEBUG_EN=1)

add_executable(ecb-slave-c-server
    main.cpp
    safe-c/safe_c.c
    crc/crc32.c
    ecb-slave/ecb-slave.c
    ecb-slave/framer7b.c
    raiden/raiden.c
    serdes/serdes.c
    serial/serial.cc
    serial/impl/win.cc
    serial/impl/unix.cc
    serial/impl/list_ports/list_ports_win.cc
    serial/impl/list_ports/list_ports_linux.cc
    serial/impl/list_ports/list_ports_osx.cc)

target_link_libraries(ecb-slave-c-server Setupapi.lib Ws2_32.lib)

if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET ecb-slave-c-server PROPERTY CXX_STANDARD 20)
endif()
