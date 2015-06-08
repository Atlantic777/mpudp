#include "tests/eth_utils.h"
#include "net_utils.h"
#include "eth_utils.h"
#include <CUnit/CUnit.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

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

    eth_build_frame(frame, dst_mac, src_mac, eth_type);
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
    int res = eth_build_frame(&frame, dst_mac_s, src_mac_s, type);

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

void test_eth_send_frame()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    eth_frame_t frame;

    // open dump file
    pcap_t *dev = pcap_open_dead(DLT_EN10MB, 1024);
    if(dev == NULL) puts(errbuf);

    pcap_dumper_t *dump = pcap_dump_open(dev, "dump.pcap");
    if(dump == NULL) puts(errbuf);

    // create dummy eth frame
    prepare_sample_frame(&frame);
    unsigned char *buff;
    int len = eth_frame_len(&frame);
    buff = malloc(len);
    eth_frame2chars(&frame, &buff);

    // construct pcap pkt header
    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec = time(NULL);
    hdr.ts.tv_usec = 0;
    hdr.caplen = len;
    hdr.len = len;

    // write dummy frame and flush dumper
    pcap_dump((unsigned char*)dump, &hdr, buff);
    pcap_dump_flush(dump);

    // check if it's written
    pcap_t *read = pcap_open_offline("dump.pcap", errbuf);
    if(read == NULL) puts(errbuf);

    struct pcap_pkthdr *header;
    const u_char *data;
    pcap_next_ex(read, &header, &data);

    CU_ASSERT_EQUAL(header->len, len);

    // close everything
    free(dev);
    free(buff);
}

void test_eth_read_frame()
{
    eth_frame_t frame;


    CU_FAIL("Finish the test!");
}
