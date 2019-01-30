include_directories(${SRC_TOP_DIR}/common_xgw)
include_directories(${SRC_TOP_DIR}/common_xgw/utils)
include_directories(${SRC_TOP_DIR}/pgw_c)
include_directories(${SRC_TOP_DIR}/sgw_c)
include_directories(${SRC_TOP_DIR}/oai_spgw_c/gtpv2-c)


add_library (PGW_C
  pgw_app.cpp
  pgw_config.cpp
  pgw_context.cpp
  pgw_paa_static.cpp
  pgw_pco.cpp
  pgw_s5s8.cpp
  pgwc_procedure.cpp
  #pgw_pcef_emulation.cpp
)

