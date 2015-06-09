#ifndef MPUDP_UTILS_H
#define MPUDP_UTILS_H

#include <pthread.h>
#include <stdint.h>

#define BUFF_LEN 10


typedef struct mpudp_buff mpudp_buff_t;
typedef struct mpudp_packet mpudp_packet_t;

struct mpudp_packet {
    uint8_t *payload;
    int    len;
    int    id;
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

int mpudp_prepare_packet(mpudp_packet_t**, uint8_t*, int);

#endif
