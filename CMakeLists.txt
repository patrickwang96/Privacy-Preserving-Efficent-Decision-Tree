cmake_minimum_required(VERSION 3.5)
project(Privacy_Preserving_Efficent_Decision_Tree)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 14)
set(COMMON_SRCS config.cc config.h decision_tree.cc decision_tree.h secret_sharing.cc secret_sharing.h test_driver.cc test_driver.h types.cc types.h utils.cc utils.h bit_compression.cpp secret_sharing_efficient_tools.cpp secret_sharing_efficient_tools.h)
set(NET_SRCS network.h network.cc)
set(CLI_SRCS test_cloud_client.cpp decision_tree_client.cpp client_main.cpp)
set(SERV_SRCS test_cloud_server.cpp decision_tree_server.cpp server_main.cpp)

# set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_library(gmp required)
include_directories(/usr/include/eigen3/ /usr/local/include/eigen3/ /usr/include/ /usr/local/include/)
link_directories(/usr/local/lib/ )

add_executable(client ${COMMON_SRCS} ${NET_SRCS} ${CLI_SRCS})
add_executable(server ${COMMON_SRCS} ${NET_SRCS} ${SERV_SRCS})

target_link_libraries(client gmp gmpxx)
target_link_libraries(server gmp gmpxx)

