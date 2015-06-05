#include "tests/ip_utils.h"
#include <CUnit/CUnit.h>
#include "ip_utils.h"

int init_ip_utils()
{
    return 0;
}

int clean_ip_utils()
{
    return 0;
}

void test_ip_build_packet()
{
    ip_packet_t packet;

    char src_ip[] = "192.168.101.1";
    char dst_ip[] = "192.168.101.2";

    ip_build_packet(&packet, src_ip, dst_ip);

    CU_FAIL("Finish the test!");
}

void test_ip_packet2chars()
{
    CU_FAIL("Finish the test!");
}

void test_ip_packet_len()
{
    CU_FAIL("Finish the test!");
}
