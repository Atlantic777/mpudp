#include "mpudp_monitor.h"
#include "mpudp_worker.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* monitor_thread(void *arg)
{
    monitor_t *m = (monitor_t*)arg;
    int i;

    char **iface_names_list;
    int num_ifaces = pcapu_find_all_devs(&iface_names_list);

    worker_t **workers = malloc(sizeof(worker_t*)*num_ifaces);

    for(i = 0; i < num_ifaces; i++)
        workers[i] = init_worker(i, iface_names_list[i], m, 0.5*i+1);

    workers[0]->dst_mac = "FF:FF:FF:FF:FF";
    workers[1]->dst_mac = "FF:FF:FF:FF:FF";

    workers[0]->dst_ip = "192.168.101.255";
    workers[1]->dst_ip = "192.168.102.255";

    workers[0]->src_port = 6660;
    workers[1]->src_port = 6661;

    workers[0]->dst_port = 8880;
    workers[1]->dst_port = 8881;



    m->num_workers = num_ifaces;
    init_bcast_buff(m);

    for(i = 0; i < num_ifaces; i++)
        spawn_worker(workers[i]);

    for(i = 0; i < num_ifaces; i++)
        pthread_join(workers[i]->tx_thread_id, NULL);
        pthread_join(workers[i]->rx_thread_id, NULL);
}

void init_monitor(monitor_t *m)
{
    // init tx buffer
    m->tx_head = 0;
    m->tx_tail = 0;
    m->tx_num  = 0;
    pthread_mutex_init(&m->tx_mx, NULL);

    // init rx buffer
    m->rx_head = 0;
    m->rx_tail = 0;
    m->tx_num  = 0;
    pthread_mutex_init(&m->rx_mx, NULL);

    // init bcast buffer
    pthread_mutex_init(&m->bcast_mx, NULL);

    // common conditional vars
    pthread_cond_init(&m->tx_has_data, NULL);
    pthread_cond_init(&m->tx_not_full, NULL);

    pthread_cond_init(&m->rx_has_data, NULL);
    pthread_cond_init(&m->rx_not_full, NULL);

    pthread_cond_init(&m->bcast_has_data, NULL);
    pthread_cond_init(&m->bcast_done, NULL);

    // monitor specific
    m->pkt_counter = 0;
    m->num_workers = 0;
}

void init_bcast_buff(monitor_t *m)
{

}
