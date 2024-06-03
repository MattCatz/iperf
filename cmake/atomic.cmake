include(CheckIncludeFile)
include(CheckLibraryExists)

check_include_file(stdatomic.h HAVE_STDATOMIC)

if(HAVE_STDATOMIC)
    set(HAVE_ATOMIC 1 CACHE INTERNAL "STD::Atomic header files")
else()
    find_library(ATOMIC atomic REQUIRED)
    set(HAVE_ATOMIC 1 CACHE INTERNAL "lib::Atomic header files")
endif()
