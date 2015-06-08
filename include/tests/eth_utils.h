#ifndef TEST_ETH_UTILS_H
#define TEST_ETH_UTILS_H

#define SAMPLE_SRC_MAC "00:01:02:03:04:05"
#define SAMPLE_DST_MAC "10:11:12:13:14:15"
#define SAMPLE_PAYLOAD "deadbeef"

int init_eth_utils();
int clean_eth_utils();

void test_eth_build_frame();
void test_eth_frame2chars();
void test_eth_frame_len();
void test_eth_set_data();
void test_eth_send_frame();
void test_eth_read_frame();

#endif
