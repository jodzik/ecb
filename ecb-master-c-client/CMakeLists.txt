cmake_minimum_required(VERSION 3.28)

project(ecb-master-c-client C CXX)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions(SAFE_C_LOG_EN__DBG=1)
add_compile_definitions(SAFE_C_LOG_EN__INF=1)
add_compile_definitions(SAFE_C_LOG_EN__WRN=1)
add_compile_definitions(SAFE_C_LOG_EN__ERR=1)
add_compile_definitions(CONFIG_ECBM_MAX_PAYLOAD_SIZE=1024)

add_subdirectory(safe-c)
add_subdirectory(byteorder-c)
add_subdirectory(crc-c)
add_subdirectory(framer7b-c)
add_subdirectory(ecbm-c)

# Cache vars, not normal vars: sockpp resets the CMP0077 policy, so its option() would clobber them.
set(SOCKPP_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(SOCKPP_BUILD_STATIC ON CACHE BOOL "" FORCE)
add_subdirectory(sockpp)

add_executable(ecb-master-c-client
    main.cpp
)

target_link_libraries(ecb-master-c-client ecbm-c sockpp-static)
