#include <CUnit/CUnit.h>
#include "tests/udp_utils.h"
#include "udp_utils.h"
#include <stdint.h>

int init_udp_utils()
{
    return 0;
}

int clean_udp_utils()
{
    return 0;
}

void test_udp_build_dgram_hdr()
{
    udp_dgram_t dgram;
    uint16_t src_port = 2048;
    uint16_t dst_port = 8888;

    udp_build_dgram_hdr(&dgram, src_port, dst_port);

    CU_ASSERT_EQUAL(dgram.src_port, src_port);
    CU_ASSERT_EQUAL(dgram.dst_port, dst_port);
    CU_ASSERT_EQUAL(dgram.len, 8);
    CU_ASSERT_EQUAL(dgram.crc, 0);
    CU_ASSERT_PTR_NULL(dgram.data);
}

void test_udp_build_pseudo_hdr()
{
    udp_pseudo_hdr_t pseudo_hdr;

    char src_ip[] = "192.168.1.1";
    char dst_ip[] = "192.168.1.2";

    udp_build_pseudo_hdr(&pseudo_hdr, src_ip, dst_ip);

    CU_ASSERT_EQUAL(pseudo_hdr.src_ip[0], 192);
    CU_ASSERT_EQUAL(pseudo_hdr.src_ip[3], 1);

    CU_ASSERT_EQUAL(pseudo_hdr.dst_ip[0], 192);
    CU_ASSERT_EQUAL(pseudo_hdr.dst_ip[3], 2);

    CU_ASSERT_EQUAL(pseudo_hdr.len[1], 20);
}

void test_udp_build_dgram()
{
    CU_FAIL("Finish the test!");
}

void test_udp_dgram2chars()
{
    // build whole dgram
    // call 2 chars
    // check it
    CU_FAIL("Finish the test!");
}

void test_udp_dgram_len()
{
    CU_FAIL("Finish the test!");
}
