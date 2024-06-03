link_libraries(iperf)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter")

add_executable(t_api t_api.c)
add_test(NAME "Test public API" COMMAND $<TARGET_FILE:t_api>)

add_executable(t_timer t_timer.c)
add_test(NAME "Test timer API" COMMAND $<TARGET_FILE:t_timer>)

add_executable(t_units t_units.c)
add_test(NAME "Test units API" COMMAND $<TARGET_FILE:t_units>)

add_executable(t_uuid t_uuid.c)
add_test(NAME "Test uuid API" COMMAND $<TARGET_FILE:t_uuid>)

if(OPENSSL)
        add_executable(t_auth t_auth.c)
        add_test(NAME "Test auth API" COMMAND $<TARGET_FILE:t_auth>)
endif()