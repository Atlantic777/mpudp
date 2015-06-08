#include <stdio.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "tests/eth_utils.h"
#include "tests/net_utils.h"
#include "tests/pcap_utils.h"
#include "tests/udp_utils.h"
#include "tests/ip_utils.h"

int main() {
    check_root();

    CU_initialize_registry();

    CU_pSuite eth_utils_suite, net_utils_suite, pcap_utils_suite,
              udp_utils_suite, ip_utils_suite;

    /******* Suites *******/
    eth_utils_suite = CU_add_suite("eth utils",
                                    init_eth_utils,
                                    clean_eth_utils);

    net_utils_suite = CU_add_suite("net utils",
                                    init_net_utils,
                                    clean_net_utils);

    pcap_utils_suite = CU_add_suite("pcap utils",
                                    init_pcap_utils,
                                    clean_pcap_utils);

    ip_utils_suite = CU_add_suite("ip utils",
                                    init_ip_utils,
                                    clean_ip_utils);

    udp_utils_suite = CU_add_suite("udp utils",
                                    init_udp_utils,
                                    clean_udp_utils);


    /******* ETH utils *****/
    CU_add_test(eth_utils_suite, "Build eth frame",
                test_eth_build_frame);
    CU_add_test(eth_utils_suite, "eth frame to chars",
                test_eth_frame2chars);
    CU_add_test(eth_utils_suite, "eth frame length",
                test_eth_frame_len);
    CU_add_test(eth_utils_suite, "eth set data",
                test_eth_set_data);
    CU_add_test(eth_utils_suite, "eth send an eth frame",
                test_eth_send_frame);
    CU_add_test(eth_utils_suite, "eth read frame",
                test_eth_read_frame);

    /******* NET utils ******/
    CU_add_test(net_utils_suite, "Parse MAC addr and store to char array",
                test_mac2chars);
    CU_add_test(net_utils_suite, "Make sure to fail on too short MAC string",
                test_mac2chars_shorter);
    CU_add_test(net_utils_suite, "Detected malformated MAC addr",
                test_mac2chars_malformated);
    CU_add_test(net_utils_suite, "Test raw MAC bytes printing to string",
                test_chars2mac);

    /******* PCAP utils ******/
    CU_add_test(pcap_utils_suite, "Get any apropriate interface",
                test_pcapu_find_any);
    CU_add_test(pcap_utils_suite, "Get iface MAC as string",
                test_read_if_mac_s);
    CU_add_test(pcap_utils_suite, "Find iface by name",
                test_find_by_name);

    /******* IP utils ******/
    CU_add_test(ip_utils_suite, "Set common IP hdr values",
                test_ip_set_common);
    CU_add_test(ip_utils_suite, "Build an IP packet",
                test_ip_build_packet);
    CU_add_test(ip_utils_suite, "ip packet to chars",
                test_ip_packet2chars);
    CU_add_test(ip_utils_suite, "ip packet len",
                test_ip_packet_len);
    CU_add_test(ip_utils_suite, "IP set data",
                test_ip_set_data);
    CU_add_test(ip_utils_suite, "IP packet to chars, with payload",
                test_ip_packet2chars_payload);
    CU_add_test(ip_utils_suite, "IP read packet",
                test_ip_read_packet);

    /******* UDP utils ******/
    CU_add_test(udp_utils_suite, "Build an UDP dgram header",
                test_udp_build_dgram_hdr);
    CU_add_test(udp_utils_suite, "Build an UDP dgram pseudo header",
                test_udp_build_pseudo_hdr);
    CU_add_test(udp_utils_suite, "Build an UDP dgram",
                test_udp_build_dgram);
    CU_add_test(udp_utils_suite, "udp set data",
                test_udp_set_data);
    CU_add_test(udp_utils_suite, "udp dgram to chars",
                test_udp_dgram2chars);
    CU_add_test(udp_utils_suite, "udp dgram length",
                test_udp_dgram_len);
    CU_add_test(udp_utils_suite, "udp read dgram",
                test_udp_read_dgram);

    /******* test runner setup ******/
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return CU_get_error();
}
