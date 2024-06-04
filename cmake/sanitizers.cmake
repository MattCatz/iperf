include(CheckCCompilerFlag)
include(CheckLinkerFlag)

option(sanitizers "Enables AddressSanitizer and UndefinedBehaviorSanitizer." OFF)
option(sanitizers_threads "Enable ThreadSanitizer" OFF)
if (sanitizers)
    check_linker_flag(C -fsanitize=undefined HAVE_LINKER_UBSAN)
    if(HAVE_LINKER_UBSAN)
        add_link_options(-fsanitize=undefined)
    endif()

    check_c_compiler_flag(-fsanitize=undefined HAVE_COMPILER_UBSAN)
    if(HAVE_COMPILER_UBSAN)
        add_compile_options(-fsanitize=undefined)
    endif()

    check_linker_flag(C -fsanitize=address HAVE_LINKER_ADDRSAN)
    if(HAVE_LINKER_ADDRSAN)
        add_link_options(-fsanitize=address)
    endif()

    check_c_compiler_flag(-fsanitize=undefined HAVE_COMPILER_ADDRSAN)
    if(HAVE_COMPILER_ADDRSAN)
        add_compile_options(-fsanitize=address)
    endif()
endif()

if (sanitizers_threads)
    check_linker_flag(C -fsanitize=thread HAVE_LINKER_THREADSAN)
    if(HAVE_LINKER_THREADSAN)
        add_link_options(-fsanitize=thread)
    endif()

    check_c_compiler_flag(-fsanitize=thread HAVE_COMPILER_THREADSAN)
    if(HAVE_COMPILER_THREADSAN)
        add_compile_options(-fsanitize=thread)
    endif()
endif()

if(HAVE_COMPILER_ADDRSAN OR HAVE_COMPILER_UBSAN OR HAVE_COMPILER_THREADSAN)
    add_compile_options( 
        -fno-omit-frame-pointer
        -fno-sanitize-recover
    )
endif()