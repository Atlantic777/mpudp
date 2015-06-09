#include "mpudp_monitor.h"
#include "mpudp_worker.h"
#include <pthread.h>
#include <stdio.h>

void* monitor_thread(void *arg)
{
    monitor_t *m = (monitor_t*)arg;

    worker_t *w1 = init_worker(1, "wlan2", m, 1);

    w1->dst_port = 8880;
    w1->dst_mac = "00:c0:ca:59:70:0e";
    w1->dst_ip = "192.168.101.2";

    spawn_worker(w1);

    worker_t *w2 = init_worker(2, "wlan4", m, 1.5);

    w2->dst_port = 8888;
    w2->dst_mac = "00:0f:13:97:11:fa";
    w2->dst_ip = "192.168.102.2";

    spawn_worker(w2);

    pthread_join(w1->tx_thread_id, NULL);
    pthread_join(w2->tx_thread_id, NULL);
}

void init_monitor(monitor_t *m)
{
    init_buffer(&m->tx_buff);
    init_buffer(&m->rx_buff);
    m->pkt_counter = 0;
}
