#ifndef TEST_UDP_UTILS_H
#define TEST_UDP_UTILS_H

int init_udp_utils();
int clean_udp_utils();

void test_udp_build_dgram_hdr();
void test_udp_build_pseudo_hdr();
void test_udp_build_dgram();
void test_udp_set_data();
void test_udp_dgram2chars();
void test_udp_dgram_len();
void test_udp_read_dgram();

#endif
