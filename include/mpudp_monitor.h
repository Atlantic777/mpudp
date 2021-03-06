#ifndef MONITOR_H
#define MONITOR_H

#include "mpudp_utils.h"
#include "mpudp_worker.h"
#include <pthread.h>

typedef struct monitor monitor_t;
typedef struct bcast_buff bcast_buff_t;
typedef struct worker worker_t;

struct bcast_buff {
    mpudp_packet_t *packet;
    uint8_t *checkin;
    pthread_mutex_t mx;
    pthread_cond_t  new_data;
    pthread_cond_t  bcast_done;
};

struct monitor {
    pthread_t    id;
    pthread_t    config_announcer_id;
    pthread_t    config_receiver_id;

    mpudp_packet_t *tx_data[BUFF_LEN];
    int  tx_head;
    int  tx_tail;
    int  tx_num;
    pthread_mutex_t tx_mx;

    mpudp_packet_t *rx_data[BUFF_LEN];
    int  rx_head;
    int  rx_tail;
    int  rx_num;
    int  user_expected_id;
    pthread_mutex_t rx_mx;

    mpudp_packet_t *esc_data[BUFF_LEN*2];
    int esc_head;
    int esc_tail;
    int esc_num;
    pthread_mutex_t esc_mx;

    mpudp_packet_t *bcast_data;
    uint8_t *checkin;

    pthread_cond_t tx_has_data;
    pthread_cond_t tx_not_full;

    pthread_cond_t rx_has_data;
    pthread_cond_t rx_not_full;

    pthread_cond_t bcast_done;

    mpudp_config_t *local_config;
    pthread_mutex_t local_config_mx;
    pthread_cond_t  local_config_changed;

    mpudp_config_t *remote_config;
    pthread_mutex_t remote_config_mx;
    pthread_cond_t  remote_config_changed;

    worker_t **workers;

    int  pkt_counter;
    int  num_workers;
};

void* monitor_thread(void*);
void* monitor_config_announcer(void*);
void* monitor_config_receiver(void*);
void init_monitor(monitor_t *);
void bcast_push(monitor_t*, mpudp_packet_t*);
int bcast_empty(monitor_t*);
void reconfigure_workers(monitor_t*);
void match_workers(monitor_t*);

#endif
