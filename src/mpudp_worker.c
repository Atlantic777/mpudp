#include "mpudp_worker.h"
#include <stdio.h>

void* worker_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    mpudp_buff_t *buff = &w->m->buff;

    while(1)
    {
        pthread_mutex_lock(&buff->mx);
        while(buff->num <= 0)
            pthread_cond_wait(&buff->empty, &buff->mx);

        printf("Worker %lu got it!\n", (unsigned long)w->id);
        buff->num--;
        pthread_mutex_unlock(&buff->mx);

        pthread_cond_signal(&buff->full);

        sleep(1);
        puts("sending finished!");
    }
}

void init_worker(worker_t *w)
{
    init_buffer(&w->buff);
}
