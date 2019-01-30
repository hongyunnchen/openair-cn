include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_TOP_DIR}/common_xgw)
include_directories(${SRC_TOP_DIR}/common_xgw/itti)
include_directories(${SRC_TOP_DIR}/oai_spgw_c)
include_directories(${SRC_TOP_DIR}/../build/git_submodules/spdlog/include)


set(CN_UTILS_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/async_shell_cmd.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/enum_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/if.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/mcc_mnc_itu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pid_file.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/string.cpp
    )


add_library(CN_UTILS ${CN_UTILS_SRC})


