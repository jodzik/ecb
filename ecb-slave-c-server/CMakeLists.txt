cmake_minimum_required(VERSION 3.28)

project(ecb-slave-c-server C CXX)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions(SAFE_C_LOG_EN__DBG=1)
add_compile_definitions(SAFE_C_LOG_EN__INF=1)
add_compile_definitions(SAFE_C_LOG_EN__WRN=1)
add_compile_definitions(SAFE_C_LOG_EN__ERR=1)
add_compile_definitions(CONFIG_ECBS_MAX_PAYLOAD_SIZE=1024)
add_compile_definitions(CONFIG_ECBS_MAX_ENDPOINTS=16)

add_subdirectory(safe-c)
add_subdirectory(byteorder-c)
add_subdirectory(crc-c)
add_subdirectory(framer7b-c)
add_subdirectory(ecbs-c)

add_executable(ecb-slave-c-server
    main.cpp
)

target_link_libraries(ecb-slave-c-server ecbs-c)
