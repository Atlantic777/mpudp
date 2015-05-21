find_library(pcap pcap)
add_executable(a.out prog.c)
target_link_libraries(a.out pcap)
