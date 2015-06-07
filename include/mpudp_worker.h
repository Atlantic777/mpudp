#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include "mpudp_utils.h"
#include "mpudp_monitor.h"

typedef struct worker worker_t;

struct worker {
    int id;
    pthread_t rx_thread_id;
    pthread_t tx_thread_id;
    mpudp_buff_t rx_buff;
    mpudp_buff_t tx_buff;
    monitor_t *m;
    int choke;
};

void* worker_tx_thread(void *arg);
worker_t* spawn_worker(int, monitor_t*, float);

#endif
