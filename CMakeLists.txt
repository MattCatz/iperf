cmake_minimum_required(VERSION 3.22)

# Project name and a few useful settings. Other commands can pick up the results
project(
  iperf
  VERSION 3.17
  DESCRIPTION "An example project with CMake"
  LANGUAGES C)

set(CMAKE_C_STANDARD 11)

option(lto "Perform LTO" ON)
option(pic "Generate PIC objects" ON)
option(perf "Structure the code for profiling with perf" ON)

if(lto)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

if(pic)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -g)

if (perf)
  add_compile_options( -Og -fno-eliminate-unused-debug-symbols -gdwarf-3 -fno-omit-frame-pointer)
else()
  add_compile_options(-O3)
endif()

include(CTest)
include(cmake/configure.cmake)
include(cmake/atomic.cmake)
include(cmake/sctp.cmake)
include(cmake/openssl.cmake)
include(cmake/sanitizers.cmake)
include(cmake/cjson.cmake)

configure_file(config/iperf_config.h.in config/iperf_config.h @ONLY)
configure_file(config/version.h.in config/version.h @ONLY)
include_directories(${CMAKE_BINARY_DIR}/config)

if(BUILD_TESTING)
  enable_testing()
  add_subdirectory(test)
endif()

# install(TARGETS ${PROJECT_NAME}
#         ARCHIVE DESTINATION lib
#         PUBLIC_HEADER DESTINATION include)

# install(TARGETS iperf3 RUNTIME DESTINATION bin)

add_subdirectory(src)