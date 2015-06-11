#include "tests/mpudp_utils.h"
#include "mpudp_monitor.h"
#include "mpudp_utils.h"
#include <CUnit/CUnit.h>
#include <string.h>
#include <stdlib.h>

int init_mpudp_utils()
{
    return 0;
}

int clean_mpudp_utils()
{
    return 0;
}

monitor_t* get_sample_monitor()
{
    monitor_t *m = malloc(sizeof(monitor_t));

    m->num_workers = 2;

    m->workers = malloc(sizeof(worker_t*)*2);
    m->workers[0] = malloc(sizeof(worker_t));
    m->workers[1] = malloc(sizeof(worker_t));

    worker_t *w1 = m->workers[0];
    worker_t *w2 = m->workers[1];

    // first worker init
    strcpy(w1->name, "wlan0");

    w1->src_mac = malloc(MAC_LEN_S);
    strcpy(w1->src_mac, "00:01:02:03:04:05");

    w1->src_ip = malloc(strlen("1.1.1.1"));
    strcpy(w1->src_ip, "1.1.1.1");

    w1->src_port = 8881;

    // second worker init
    strcpy(w2->name, "wlan2");

    w2->src_mac = malloc(MAC_LEN_S);
    strcpy(w2->src_mac, "10:11:12:13:14:15");

    w2->src_ip = malloc(strlen("2.2.2.2"));
    strcpy(w2->src_ip, "2.2.2.2");

    w2->src_port = 8882;

    return m;
}

void test_mpudp_build_config()
{
    monitor_t *m = get_sample_monitor();

    mpudp_config_t config;
    config.id = 0;
    mpudp_build_config(m, &config);

    CU_ASSERT_EQUAL(config.if_list[0].port, 8881);

    char mac_s[MAC_LEN_S];
    chars2mac(config.if_list[0].mac, mac_s);
    CU_ASSERT_EQUAL(strcmp(mac_s, m->workers[0]->src_mac), 0);
}

void test_mpudp_config2chars()
{
    monitor_t *m = get_sample_monitor();

    mpudp_config_t config;
    config.id = 0;
    mpudp_build_config(m, &config);

    uint8_t *payload;

    mpudp_config2chars(&config, &payload);

    CU_ASSERT_EQUAL(payload[0], 0);
    CU_ASSERT_EQUAL(payload[1], 2);
    CU_ASSERT_EQUAL(strncmp(m->workers[0]->name, payload+2, 6), 0);
}

void test_mpudp_chars2config()
{

    monitor_t *m = get_sample_monitor();

    mpudp_config_t s_conf;
    s_conf.id = 0;
    mpudp_build_config(m, &s_conf);

    uint8_t *payload;
    int len = mpudp_config2chars(&s_conf, &payload);

    mpudp_config_t r_conf;
    mpudp_chars2config(&r_conf, payload, len);

    int D_LEN = MPUDP_IFACE_DESC_LEN;

    CU_ASSERT_EQUAL(r_conf.id, 0);
    CU_ASSERT_EQUAL(memcmp(&s_conf.if_list[0], &r_conf.if_list[0], D_LEN), 0);
    CU_ASSERT_EQUAL(memcmp(&s_conf.if_list[1], &r_conf.if_list[1], D_LEN), 0);
}
