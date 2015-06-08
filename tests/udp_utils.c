#include <CUnit/CUnit.h>
#include "tests/udp_utils.h"
#include "udp_utils.h"
#include <stdint.h>
#include <stdlib.h>

uint16_t t_udp_src_port = 2048;
uint16_t t_udp_dst_port = 8888;

char t_udp_src_ip[] = "192.168.1.1";
char t_udp_dst_ip[] = "192.168.1.2";

int init_udp_utils()
{
    return 0;
}

int clean_udp_utils()
{
    return 0;
}

udp_dgram_t* get_sample_dgram()
{
    udp_dgram_t *dgram = malloc(sizeof(udp_dgram_t));

    udp_build_dgram(dgram, t_udp_src_port, t_udp_dst_port,
                            t_udp_src_ip, t_udp_dst_ip);

    unsigned char msg[] = "Hello world!";
    int target_len = strlen(msg);

    udp_set_data(dgram, msg, target_len);

    return dgram;
}

void test_udp_build_dgram_hdr()
{
    udp_dgram_t dgram;

    udp_build_dgram_hdr(&dgram, t_udp_src_port, t_udp_dst_port);

    CU_ASSERT_EQUAL(dgram.src_port, t_udp_src_port);
    CU_ASSERT_EQUAL(dgram.dst_port, t_udp_dst_port);
    CU_ASSERT_EQUAL(dgram.len, 8);
    CU_ASSERT_EQUAL(dgram.crc, 0);
    CU_ASSERT_PTR_NULL(dgram.data);
}

void test_udp_build_pseudo_hdr()
{
    udp_pseudo_hdr_t pseudo_hdr;

    udp_build_pseudo_hdr(&pseudo_hdr, t_udp_src_ip, t_udp_dst_ip);

    CU_ASSERT_EQUAL(pseudo_hdr.src_ip[0], 192);
    CU_ASSERT_EQUAL(pseudo_hdr.src_ip[3], 1);

    CU_ASSERT_EQUAL(pseudo_hdr.dst_ip[0], 192);
    CU_ASSERT_EQUAL(pseudo_hdr.dst_ip[3], 2);

    CU_ASSERT_EQUAL(pseudo_hdr.len[1], 20);
}

void test_udp_build_dgram()
{
    udp_dgram_t dgram;

    udp_build_dgram(&dgram, t_udp_src_port, t_udp_dst_port,
                            t_udp_src_ip, t_udp_dst_ip);

    CU_ASSERT_EQUAL(dgram.src_port, t_udp_src_port);
    CU_ASSERT_EQUAL(dgram.dst_port, t_udp_dst_port);
}

void test_udp_set_data()
{
    udp_dgram_t *dgram = get_sample_dgram();

    unsigned char msg[] = "Hello world!";
    int target_len = strlen(msg);

    udp_set_data(dgram, msg, target_len);

    CU_ASSERT_EQUAL(strncmp(msg, dgram->data, target_len), 0);
}

void test_udp_dgram2chars()
{
    udp_dgram_t *dgram = get_sample_dgram();

    unsigned char *payload;
    int udp_len = udp_dgram2chars(dgram, &payload);

    CU_ASSERT_EQUAL(payload[0]<<8 | payload[1], t_udp_src_port);
    CU_ASSERT_EQUAL(payload[2]<<8 | payload[3], t_udp_dst_port);
    CU_ASSERT_EQUAL(memcmp(payload+8, dgram->data, dgram->len-8), 0);
}

void test_udp_dgram_len()
{
    udp_dgram_t *dgram = get_sample_dgram();

    int target_len = strlen("Hello world!");

    CU_ASSERT_EQUAL(target_len+8, dgram->len);
}

void test_udp_read_dgram()
{
    udp_dgram_t *s_dgram = get_sample_dgram();

    unsigned char *payload;
    int udp_len = udp_dgram2chars(s_dgram, &payload);

    udp_dgram_t r_dgram;
    udp_read_dgram(&r_dgram, payload, udp_len);

    CU_ASSERT_EQUAL(memcmp(&r_dgram, s_dgram, 8), 0);
    CU_ASSERT_EQUAL(memcmp(r_dgram.data, s_dgram->data, s_dgram->len-8),0);
}
