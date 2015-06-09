#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include "mpudp_utils.h"
#include "mpudp_monitor.h"
#include <pcap.h>

typedef struct worker worker_t;

struct worker {
    int id;
    pthread_t rx_thread_id;
    pthread_t tx_thread_id;
    mpudp_buff_t rx_buff;
    mpudp_buff_t tx_buff;
    monitor_t *m;
    int choke;
    char *src_ip;
    char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    char *src_mac;
    char *dst_mac;
    pcap_t    *if_handle;
    pcap_if_t *if_desc;
};

void* worker_tx_thread(void *arg);
worker_t* init_worker(int, char*, monitor_t*, float);
int spawn_worker(worker_t* spawn_worker);
int worker_send_packet(worker_t*, mpudp_packet_t*);

#endif
