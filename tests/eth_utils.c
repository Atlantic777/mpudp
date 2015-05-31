#include "tests/eth_utils.h"
#include "net_utils.h"
#include "eth_utils.h"
#include <CUnit/CUnit.h>
#include <string.h>
#include <stdlib.h>

int init_eth_utils()
{
    return 0;
}

int clean_eth_utils()
{
    return 0;
}

void prepare_empty_frame(eth_frame_t *frame)
{
    unsigned char src_mac[] = SAMPLE_SRC_MAC;
    unsigned char dst_mac[] = SAMPLE_DST_MAC;
    unsigned char eth_type[] = {0x80, 0x00};

    eth_compile_frame(frame, dst_mac, src_mac, eth_type);
}

void prepare_sample_frame(eth_frame_t *frame)
{
    unsigned char payload[] = SAMPLE_PAYLOAD;

    prepare_empty_frame(frame);
    eth_set_data(frame, payload, strlen(payload));
}

void test_eth_build_frame()
{
    char src_mac_s[MAC_LEN_S] = "00:01:02:03:04:05";
    char dst_mac_s[MAC_LEN_S] = "10:11:12:13:14:15";

    unsigned char dst_mac[MAC_LEN];
    unsigned char src_mac[MAC_LEN];

    mac2chars(src_mac_s, src_mac);
    mac2chars(dst_mac_s, dst_mac);

    unsigned char type[2] = {0x80, 0x00};

    eth_frame_t frame;
    int res = eth_compile_frame(&frame, dst_mac_s, src_mac_s, type);

    CU_ASSERT_EQUAL(res, 0);
    CU_ASSERT_EQUAL(memcmp(frame.src, src_mac, MAC_LEN), 0);
    CU_ASSERT_EQUAL(memcmp(frame.dst, dst_mac, MAC_LEN), 0);
    CU_ASSERT_EQUAL(memcmp(frame.type, type, 2), 0);
    CU_ASSERT_PTR_NULL(frame.data);
    CU_ASSERT_EQUAL(frame.data_len, 0);
}

void test_eth_set_data()
{
    eth_frame_t frame;
    prepare_sample_frame(&frame);

    unsigned char payload[] = SAMPLE_PAYLOAD;

    CU_ASSERT_EQUAL(memcmp(frame.data, payload, strlen(payload)), 0);
    CU_ASSERT_EQUAL(frame.data_len, strlen(payload));
}

void test_eth_frame2chars()
{
    eth_frame_t frame;
    prepare_empty_frame(&frame);
    unsigned char *result = malloc(eth_frame_len(&frame));

    mac2chars(SAMPLE_DST_MAC, result);
    mac2chars(SAMPLE_SRC_MAC, result+MAC_LEN);
    result[2*MAC_LEN]   = 0x80;
    result[2*MAC_LEN+1] = 0x00;
    memcpy(result+ETH_FRAME_PREFIX_LEN,SAMPLE_PAYLOAD, strlen(SAMPLE_PAYLOAD));


    unsigned char *calculated_result;

    eth_frame2chars(&frame, &calculated_result);

    CU_ASSERT_EQUAL(memcmp(result,
                           calculated_result,
                           eth_frame_len(&frame)),
                    0);

    free(result);
}

void test_eth_frame_len()
{
    eth_frame_t frame;
    prepare_sample_frame(&frame);
    int target_len = ETH_FRAME_PREFIX_LEN+strlen(SAMPLE_PAYLOAD);

    CU_ASSERT_EQUAL(eth_frame_len(&frame), target_len);
}
