cmake_minimum_required(VERSION 3.15)
project(Privacy_Preserving_Efficent_Decision_Tree)

set(CMAKE_CXX_STANDARD 11)
find_library(gmp required)
include_directories(/usr/include/eigen3/ /usr/local/include/ ../libOTe/ ../libOTe/cryptoTools ../libOTe/cryptoTools/thirdparty/linux/boost ../libOTe/cryptoTools/thirdparty/linux/miracl)
link_directories(/usr/local/lib/ ../libOTe/lib/ ../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib)

add_executable(Decision-Tree config.cc config.h decision_tree.cc decision_tree.h main.cc
        secret_sharing.cc secret_sharing.h test_driver.cc
        test_driver.h types.cc types.h utils.cc utils.h network.cc network.h test_cloud_client.cpp decision_tree_client.cpp decision_tree_server.cpp)

target_compile_options(Decision-Tree PRIVATE "-Wall")
TARGET_LINK_LIBRARIES(Decision-Tree pthread gmp gmpxx)
