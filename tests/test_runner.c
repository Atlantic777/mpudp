#include <stdio.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "tests/eth_utils.h"
#include "tests/net_utils.h"

int main() {
    CU_initialize_registry();

    CU_pSuite eth_utils_suite, net_utils_suite;

    /******* Suites *******/
    eth_utils_suite = CU_add_suite("eth utils",
                                    init_eth_utils,
                                    clean_eth_utils);

    net_utils_suite = CU_add_suite("net utils",
                                    init_net_utils,
                                    clean_net_utils);

    /******* ETH utils *****/
    CU_add_test(eth_utils_suite, "Build eth frame",
                test_eth_build_frame);

    /******* NET utils ******/
    CU_add_test(net_utils_suite, "Parse MAC addr and store to char array",
                test_mac2chars);
    CU_add_test(net_utils_suite, "Make sure to fail on too short MAC string",
                test_mac2chars_shorter);
    CU_add_test(net_utils_suite, "Detected malformated MAC addr",
                test_mac2chars_malformated);

    /******* test runner setup ******/
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return CU_get_error();
}
