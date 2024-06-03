include(CheckIncludeFile)

option(auth "Include authentication features" ON)
if(auth)
    find_library(OPENSSL ssl REQUIRED)
    find_library(CRYPTO crypto REQUIRED)
    check_include_file("openssl/bio.h" HAVE_SSL)
endif()
