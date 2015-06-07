#include "mpudp_worker.h"
#include <stdio.h>
#include <stdlib.h>

void* worker_tx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    mpudp_buff_t *buff = &w->m->tx_buff;

    while(1)
    {
        pthread_mutex_lock(&buff->mx);
        while(buff->num <= 0)
            pthread_cond_wait(&buff->empty, &buff->mx);

        int id = buff->data[buff->tail]->id;


        buff->num--;
        buff->tail =  (buff->tail + 1) % BUFF_LEN;
        pthread_mutex_unlock(&buff->mx);

        pthread_cond_signal(&buff->full);

        usleep(w->choke);

        printf("Worker got it! Sending: %3d ", id);
        printf("tail: %3d, head: %3d\n", buff->tail, buff->head);
    }
}

void* worker_rx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    mpudp_buff_t *buff = &w->m->rx_buff;

}

worker_t* spawn_worker(int id, monitor_t *m, float choke)
{
    worker_t *w = malloc(sizeof(worker_t));
    init_buffer(&w->tx_buff);
    w->m = m;
    w->choke = choke*1000000;

    pthread_create(&w->tx_thread_id, NULL, &worker_tx_thread, w);
    pthread_create(&w->rx_thread_id, NULL, &worker_rx_thread, w);

    return w;
}
