include(CheckIncludeFile)
include(CheckTypeSize)


option(sctp "Include sctp features" ON)
if(sctp)
    find_library(SCTP sctp REQURED)
    check_include_file("netinet/sctp.h" HAVE_SCTP_H)
    check_type_size("struct sctp_assoc_value" HAVE_STRUCT_SCTP_ASSOC_VALUE)
endif()
