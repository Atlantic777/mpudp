#include <CUnit/CUnit.h>
#include "net_utils.h"
#include "tests/net_utils.h"


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
    unsigned char address[] = "00:01:02:03:04:05";
    unsigned char dest[MAC_LEN];

    mac2chars(address, dest);

    int i = 0;

    for(i = 0; i < MAC_LEN; i++)
    {
        CU_ASSERT_EQUAL(dest[i], i);
    }
}

void test_mac2chars_shorter()
{
    unsigned char address[] = "00:01:02";
    unsigned char dest[MAC_LEN];

    int retval = mac2chars(address, dest);

    CU_ASSERT_EQUAL(retval, -1);
}
