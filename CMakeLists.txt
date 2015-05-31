cmake_minimum_required(VERSION 2.8)

project(mpudp)

# global libs
find_library(pcap pcap)
find_library(cunit cunit)
include_directories(include)

# common local libs
add_library(net_utils src/net_utils.c)
add_library(eth_utils src/eth_utils.c)
add_library(pcap_utils src/pcap_utils.c)
target_link_libraries(pcap_utils pcap)

# client/server executables
add_executable(mpudp src/main.c)
target_link_libraries(mpudp pcap)

# test libs
add_library(t_eth_utils tests/eth_utils.c)
target_link_libraries(t_eth_utils eth_utils net_utils)

add_library(t_net_utils tests/net_utils.c)
target_link_libraries(t_net_utils net_utils)

add_library(t_pcap_utils tests/pcap_utils.c)
target_link_libraries(t_pcap_utils net_utils pcap pcap_utils)

# test runner executable
add_executable(unit-test tests/test_runner.c)
target_link_libraries(unit-test cunit t_eth_utils t_net_utils t_pcap_utils)

# playground
add_executable(playground tests/playground.c)
target_link_libraries(playground eth_utils net_utils pcap)
