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

void test_mac2chars_malformated()
{
    unsigned char dest[MAC_LEN];

    CU_ASSERT_EQUAL(mac2chars(":::::::::::::::::", dest), -1);
    CU_ASSERT_EQUAL(mac2chars("11111111111111111", dest), -1);
}

void test_chars2mac()
{
    unsigned char mac_raw[MAC_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    char mac_string[MAC_LEN_S];
    char mac_string_correct[] = "00:01:02:03:04:05";

    int res = chars2mac(mac_raw, mac_string);
    CU_ASSERT_STRING_EQUAL(mac_string, mac_string_correct);

    CU_ASSERT_EQUAL(res, 0);
}
