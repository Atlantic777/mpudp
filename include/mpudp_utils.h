#ifndef MPUDP_UTILS_H
#define MPUDP_UTILS_H

#include <pthread.h>
#include <stdint.h>

#define BUFF_LEN 10

#define MPUDP_CONFIG 0
#define MPUDP_DATA   1
#define MPUDP_ACK    2

typedef struct mpudp_buff mpudp_buff_t;
typedef struct mpudp_packet mpudp_packet_t;
typedef struct mpudp_config mpudp_config_t;
typedef struct mpudp_if_desc mpudp_if_desc_t;

struct mpudp_packet {
    uint8_t *payload;
    int      len;
    int      id;
    uint8_t  type;
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
    uint8_t id;
    uint8_t num_if;
    mpudp_if_desc_t *if_list;
};

struct mpudp_if_desc {
    uint8_t *name;
    uint8_t *mac;
    uint32_t ip;
    uint16_t port;
};

int mpudp_prepare_packet(mpudp_packet_t**, uint8_t*, int);
int mpudp_config_matcher();

#endif
