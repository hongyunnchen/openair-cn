add_library(GTPV2C
    gtpv2c.cpp
    )

include_directories(${SRC_TOP_DIR}/oai_spgw_c/gtpv2c)
include_directories(${SRC_TOP_DIR}/common_xgw)
include_directories(${SRC_TOP_DIR}/common_xgw/itti)
include_directories(${SRC_TOP_DIR}/common_xgw/msg)
include_directories(${SRC_TOP_DIR}/oai_spgw_c/utils)
include_directories(${SRC_TOP_DIR}/oai_spgw_c)
include_directories(${SRC_TOP_DIR}/../build/git_submodules/spdlog/include)
