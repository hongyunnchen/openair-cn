
include_directories(${SRC_TOP_DIR}/common_xgw)
include_directories(${SRC_TOP_DIR}/common_xgw/itti)
include_directories(${SRC_TOP_DIR}/common_xgw/utils)
include_directories(${SRC_TOP_DIR}/sgw_c)
include_directories(${SRC_TOP_DIR}/oai_spgw_c/gtpv2-c)
include_directories(${SRC_TOP_DIR}/pfcp)

if(${SGW_AUTOTEST})
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -DSGW_AUTOTEST=1")
  add_library (SGW_C 
  mme_s11.cpp
  sgwc_app.cpp
  sgwc_config.cpp
  sgwc_eps_bearer_context.cpp
  sgwc_pdn_connection.cpp
  sgwc_procedure.cpp
  sgwc_s11.cpp
  sgwc_s5s8.cpp
  sgwc_sxa.cpp
  )
else ()
add_library (SGW_C
  sgwc_app.cpp
  sgwc_config.cpp
  sgwc_eps_bearer_context.cpp
  sgwc_pdn_connection.cpp
  sgwc_procedure.cpp
  sgwc_s11.cpp
  sgwc_s5s8.cpp
  sgwc_sxa.cpp
  )
endif ()
