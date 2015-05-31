#include "tests/pcap_utils.h"
#include <CUnit/CUnit.h>
#include <pcap.h>
#include "pcap_utils.h"
#include <net_utils.h>

int init_pcap_utils()
{
    return 0;
}

int clean_pcap_utils()
{
    return 0;
}

void test_pcapu_find_any()
{
    pcap_if_t *dev_if;
    CU_ASSERT_EQUAL(pcapu_find_any(&dev_if), 0);
}

void test_read_if_mac_s()
{
    pcap_if_t *dev_if;
    char *mac_s;
    pcapu_find_any(&dev_if);

    CU_ASSERT_PTR_NOT_NULL(pcapu_read_if_mac_s(dev_if->name, &mac_s));
}
