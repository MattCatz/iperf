set(_libiperf_private
        cjson.c
        dscp.c
        net.c
        tcp_info.c
        timer.c
        units.c
        iperf_udp.c
        iperf_tcp.c
        iperf_time.c
        iperf_util.c
        iperf_sctp.c
        iperf_locale.c
        iperf_auth.c
        iperf_pthread.c
        )

set(_libiperf_public
        iperf_api.c
        iperf_client_api.c
        iperf_error.c
        iperf_server_api.c
        )

option(static "Build static vesrion of libperf" ON)
option(shared "Build shared version of libperf" OFF)
option(binary "Build iperf3 binary" ON)

add_library(_libiperf_private OBJECT ${_libiperf_private})
set_target_properties(_libiperf_private PROPERTIES C_VISIBILITY_PRESET hidden)
target_link_libraries(_libiperf_private PUBLIC ${MATH} ${PTHREADS})

if(OPENSSL)
        target_link_libraries(_libiperf_private PUBLIC ${OPENSSL} ${CRYPTO})
endif()

if (SCTP)
        target_link_libraries(_libiperf_private PUBLIC ${SCTP})
endif()

add_library(_libiperf_public OBJECT ${_libiperf_public})
set_target_properties(_libiperf_public PROPERTIES C_VISIBILITY_PRESET default)
set_target_properties(_libiperf_public PROPERTIES PUBLIC_HEADER iperf_api.h)
target_link_libraries(_libiperf_public PUBLIC ${MATH} ${PTHREADS})
target_include_directories(_libiperf_public PUBLIC ${CMAKE_CURRENT_LIST_DIR})


if(static)
        add_library(libiperf_static STATIC $<TARGET_OBJECTS:_libiperf_public> $<TARGET_OBJECTS:_libiperf_private>)
        set_target_properties(libiperf_static PROPERTIES OUTPUT_NAME iperf)
        target_link_libraries(libiperf_static _libiperf_public _libiperf_private)
endif()

if(shared)
        add_library(libiperf_shared SHARED $<TARGET_OBJECTS:_libiperf_public> $<TARGET_OBJECTS:_libiperf_private>)
        set_target_properties(libiperf_shared PROPERTIES OUTPUT_NAME iperf)
        target_link_libraries(libiperf_shared _libiperf_public _libiperf_private)
endif()

if(shared)
        add_library(iperf ALIAS libiperf_shared)
else()
        add_library(iperf ALIAS libiperf_static)
endif()

if(binary)
        add_executable(iperf3 main.c)
        target_link_libraries(iperf3 iperf)
endif()