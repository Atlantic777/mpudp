cmake_minimum_required(VERSION 2.8)

project(mpudp)

# global libs
find_library(pcap pcap)
find_library(cunit cunit)
find_library(pthread pthread)
include_directories(include)

# common local libs
add_library(eth_utils src/eth_utils.c)
target_link_libraries(eth_utils net_utils)

add_library(ip_utils src/ip_utils.c)
add_library(udp_utils src/udp_utils.c)

add_library(net_utils src/net_utils.c)
add_library(pcap_utils src/pcap_utils.c)
target_link_libraries(pcap_utils pcap)

add_library(monitor src/mpudp_monitor.c)
target_link_libraries(monitor pcap_utils worker)

add_library(worker  src/mpudp_worker.c)
target_link_libraries(worker udp_utils ip_utils eth_utils)
target_link_libraries(worker mpudp_utils pcap_utils)
target_link_libraries(worker pcap)

add_library(mpudp_utils src/mpudp_utils.c)

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

add_library(t_ip_utils tests/ip_utils.c)
target_link_libraries(t_ip_utils ip_utils)

add_library(t_udp_utils tests/udp_utils.c)
target_link_libraries(t_udp_utils udp_utils)

add_library(t_mpudp_utils tests/mpudp_utils.c)
target_link_libraries(t_mpudp_utils mpudp_utils)


# test runner executable
add_executable(unit-test tests/test_runner.c)
target_link_libraries(unit-test cunit)
target_link_libraries(unit-test t_net_utils t_pcap_utils t_mpudp_utils)
target_link_libraries(unit-test t_eth_utils t_udp_utils t_ip_utils)

# playground
add_executable(playground tests/playground.c)
target_link_libraries(playground net_utils pcap pcap_utils)
target_link_libraries(playground ip_utils udp_utils eth_utils)
target_link_libraries(playground pthread)
target_link_libraries(playground monitor worker mpudp_utils)

# end to end tests
add_executable(t_tx_test tests/tx_test.c)
target_link_libraries(t_tx_test net_utils pcap pcap_utils pthread)
target_link_libraries(t_tx_test monitor worker mpudp_utils)

add_executable(t_udp_tx_e2e tests/udp_tx_e2e.c)
target_link_libraries(t_udp_tx_e2e pcap pcap_utils pthread)
target_link_libraries(t_udp_tx_e2e monitor worker mpudp_utils)
target_link_libraries(t_udp_tx_e2e ip_utils udp_utils eth_utils)

add_executable(t_read_addr tests/read_addr.c)
target_link_libraries(t_read_addr pcap_utils worker)

add_executable(t_worker_init tests/worker_init.c)
target_link_libraries(t_worker_init pthread monitor)

add_executable(t_rx_test tests/rx_test.c)
target_link_libraries(t_rx_test monitor pthread)

add_executable(t_file_rx_test tests/file_rx_test.c)
target_link_libraries(t_file_rx_test monitor pthread)
