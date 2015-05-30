#include "tests/eth_utils.h"
#include "net_utils.h"
#include "eth_utils.h"
#include <CUnit/CUnit.h>

int init_eth_utils()
{
    return 0;
}

int clean_eth_utils()
{
    return 0;
}

void test_eth_build_frame()
{
    char src_mac_s[MAC_LEN_S] = "00:01:02:03:04:05";
    char dst_mac_s[MAC_LEN_S] = "10:11:12:13:14:15";
    char type[2] = {0x80, 0x00};

    eth_frame_t frame;
    eth_compile_frame(&frame, dst_mac_s, src_mac_s, type);

    CU_FAIL("Finish the test...");
}
