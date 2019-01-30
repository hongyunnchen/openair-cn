set(ITTI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/itti)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/itti)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/msg)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
include_directories(${SRC_TOP_DIR}/../build/git_submodules/spdlog/include)

add_library(3GPP_COMMON_TYPES
  ${CMAKE_CURRENT_SOURCE_DIR}/common_root_types.c
  ${CMAKE_CURRENT_SOURCE_DIR}/logger.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_129.244.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_29.274.cpp
)


