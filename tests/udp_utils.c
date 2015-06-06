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

    CU_FAIL("Finish the test!");
}

void test_udp_build_dgram()
{
    CU_FAIL("Finish the test!");
}

void test_udp_dgram2chars()
{
    CU_FAIL("Finish the test!");
}

void test_udp_dgram_len()
{
    CU_FAIL("Finish the test!");
}
