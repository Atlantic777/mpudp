#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include "mpudp_utils.h"
#include "mpudp_monitor.h"

typedef struct worker worker_t;

struct worker {
    pthread_t id;
    mpudp_buff_t buff;
    monitor_t *m;
};

void* worker_thread(void *arg);
void init_worker(worker_t *);

#endif
