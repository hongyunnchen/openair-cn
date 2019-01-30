
include_directories(${SRC_TOP_DIR}/common_xgw)
include_directories(${SRC_TOP_DIR}/common_xgw/itti)
include_directories(${SRC_TOP_DIR}/common_xgw/msg)
include_directories(${SRC_TOP_DIR}/common_xgw/utils)
include_directories(${SRC_TOP_DIR}/oai_spgw_u)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/sgw_u)


add_library (SPGW_U
  spgwu_app.cpp
  spgwu_config.cpp
  spgwu_sx.cpp
  )
