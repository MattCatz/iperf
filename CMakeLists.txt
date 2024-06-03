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
option(strip "Strip objects" ON)

if(lto)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

if(pic)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "-Wall -Wextra -g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

if(strip)
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
endif()

include(CTest)
include(cmake/configure.cmake)
include(cmake/atomic.cmake)
include(cmake/sctp.cmake)
include(cmake/openssl.cmake)

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