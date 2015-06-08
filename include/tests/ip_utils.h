#ifndef TEST_IP_UTILS_H
#define TEST_IP_UTILS_H

int init_ip_utils();
int clean_ip_utils();

void test_ip_build_packet();
void test_ip_packet2chars();
void test_ip_packet_len();
void test_ip_set_common();
void test_ip_packet2chars_payload();
void test_ip_set_data();
void test_ip_read_packet();

#endif
