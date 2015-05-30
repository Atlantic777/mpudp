#include <CUnit/CUnit.h>
#include "net_utils.h"
#include "tests/net_utils.h"

unsigned char address[] = "00:01:02:03:04:05";
unsigned char dest[MAC_LEN];

int init_net_utils()
{
    return 0;
}

int clean_net_utils()
{
    return 0;
}

void test_mac2chars()
{
    mac2chars(address, dest);

    int i = 0;

    for(i = 0; i < MAC_LEN; i++)
    {
        CU_ASSERT_EQUAL(dest[i], i);
    }
}
