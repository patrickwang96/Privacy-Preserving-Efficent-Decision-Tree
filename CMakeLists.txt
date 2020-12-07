cmake_minimum_required(VERSION 3.5)
project(Privacy_Preserving_Efficent_Decision_Tree)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 14)
set(COMMON_SRCS config.cc config.h decision_tree.cc decision_tree.h secret_sharing.cc secret_sharing.h test_driver.cc test_driver.h types.cc types.h utils.cc utils.h bit_compression.cpp secret_sharing_efficient_tools.cpp secret_sharing_efficient_tools.h)
set(NET_SRCS network.h network.cc)
set(CLI_SRCS test_cloud_client.cpp decision_tree_client.cpp client_main.cpp)
set(SERV_SRCS test_cloud_server.cpp decision_tree_server.cpp server_main.cpp)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_library(gmp required)
include_directories(/usr/include/eigen3/ /usr/include/ )
# link_directories(/usr/local/lib/ ../libOTe/lib/ ../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "./build")
#add_executable(Decision-Tree config.cc config.h decision_tree.cc decision_tree.h main.cc
#        secret_sharing.cc secret_sharing.h test_driver.cc
#        test_driver.h types.cc types.h utils.cc utils.h network.cc
#        network.h test_cloud_client.cpp decision_tree_client.cpp
#        decision_tree_server.cpp test_cloud_server.cpp client_main.cpp
#        server_main.cpp)

#add_executable(test_main test_main.cpp ${NET_SRCS})
add_executable(client ${COMMON_SRCS} ${NET_SRCS} ${CLI_SRCS})
add_executable(server ${COMMON_SRCS} ${NET_SRCS} ${SERV_SRCS})

#target_compile_options(client PRIVATE "-Wall")
target_link_libraries(client gmp gmpxx)
# target_link_libraries(client pthread libOTe cryptoTools KyberOT boost_system boost_thread relic)
# target_link_libraries(server pthread libOTe cryptoTools KyberOT boost_system boost_thread relic)
target_link_libraries(server gmp gmpxx)
#target_link_libraries(test_main gmp gmpxx)

#target_compile_options(Decision-Tree PRIVATE "-Wall")
#TARGET_LINK_LIBRARIES(Decision-Tree pthread gmp gmpxx)
