#include "mpudp_monitor.h"
#include "mpudp_worker.h"
#include <pthread.h>
#include <stdio.h>

void* monitor_thread(void *arg)
{
    monitor_t *m = (monitor_t*)arg;

    worker_t  w1;
    w1.m = m;
    init_worker(&w1);
    pthread_create(&w1.id, NULL, &worker_thread, &w1);

    worker_t w2;
    w2.m = m;
    init_worker(&w2);
    pthread_create(&w2.id, NULL, &worker_thread, &w2);

    pthread_join(w1.id, NULL);
    pthread_join(w2.id, NULL);
}

void init_monitor(monitor_t *m)
{
    init_buffer(&m->buff);
}
