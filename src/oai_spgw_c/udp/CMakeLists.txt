include_directories(${SRC_TOP_DIR}/common_xgw)
include_directories(${SRC_TOP_DIR}/common_xgw/itti)
include_directories(${SRC_TOP_DIR}/oai_spgw_c/utils)


add_library(UDP_SERVER udp_server.cpp)
