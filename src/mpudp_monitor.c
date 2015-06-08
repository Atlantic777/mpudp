#include "mpudp_monitor.h"
#include "mpudp_worker.h"
#include <pthread.h>
#include <stdio.h>

void* monitor_thread(void *arg)
{
    monitor_t *m = (monitor_t*)arg;

    worker_t *w1 = spawn_worker(1, m, 0.1);
    /* worker_t *w2 = spawn_worker(2, m, 0.2); */

    pthread_join(w1->tx_thread_id, NULL);
    /* pthread_join(w2->tx_thread_id, NULL); */
}

void init_monitor(monitor_t *m)
{
    init_buffer(&m->tx_buff);
    init_buffer(&m->rx_buff);
    m->pkt_counter = 0;
}
