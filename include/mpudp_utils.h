#ifndef MPUDP_UTILS_H
#define MPUDP_UTILS_H

#include <pthread.h>
#include <stdint.h>
#include "net_utils.h"

#define BUFF_LEN 10

#define MPUDP_CONFIG 0
#define MPUDP_DATA   1
#define MPUDP_ACK    2

#define MPUDP_IFACE_DESC_LEN (6 + MAC_LEN + 4 + 2)
#define MPUDP_CONFIG_PREFIX_LEN 2

typedef struct mpudp_buff mpudp_buff_t;
typedef struct mpudp_packet mpudp_packet_t;
typedef struct mpudp_config mpudp_config_t;
typedef struct mpudp_if_desc mpudp_if_desc_t;

typedef struct monitor monitor_t;

struct mpudp_packet {
    uint8_t  type;
    uint32_t id;
    int      len;
    uint8_t *payload;
};

struct mpudp_buff {
    mpudp_packet_t* data[BUFF_LEN];
    int head;
    int tail;
    int num;

    pthread_cond_t  empty;
    pthread_cond_t  full;
    pthread_mutex_t mx;
};

struct mpudp_config {
    int8_t id;
    uint8_t num_if;
    mpudp_if_desc_t *if_list;
};

struct mpudp_if_desc {
    char name[6];
    uint8_t mac[MAC_LEN];
    uint32_t ip;
    uint16_t port;
};

int mpudp_prepare_packet(mpudp_packet_t**, uint8_t*, int);
int mpudp_config_matcher();
void mpudp_build_config(int, char**, mpudp_config_t*);
int mpudp_config2chars(mpudp_config_t*,uint8_t**);
int mpudp_chars2config(mpudp_config_t*, uint8_t*, int);
int mpudp_chars2packet(mpudp_packet_t*, uint8_t*, int len);
int mpudp_packet2chars(mpudp_packet_t*, uint8_t**);
void mpudp_send_packet(monitor_t*,uint8_t*, int);
int mpudp_recv_packet(monitor_t*,uint8_t**);
int next_packet_available(monitor_t*);
void mpudp_print_config(mpudp_config_t*);
void mpudp_print_iface_desc(mpudp_if_desc_t*);

#endif
