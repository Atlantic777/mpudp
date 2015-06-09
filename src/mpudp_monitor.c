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
    {
        printf("%d - %s\n", i, iface_names_list[i]);
        workers[i] = init_worker(i, iface_names_list[i], m, 1);
    }

    workers[0]->dst_port = 8880;
    workers[0]->dst_mac = "00:c0:ca:59:70:0e";
    workers[0]->dst_ip = "192.168.101.2";

    workers[1]->dst_port = 8888;
    workers[1]->dst_mac = "00:0f:13:97:11:fa";
    workers[1]->dst_ip = "192.168.102.2";

    for(i = 0; i < num_ifaces; i++)
        spawn_worker(workers[i]);

    for(i = 0; i < num_ifaces; i++)
        pthread_join(workers[i]->tx_thread_id, NULL);
        pthread_join(workers[i]->rx_thread_id, NULL);
}

void init_monitor(monitor_t *m)
{
    init_buffer(&m->tx_buff);
    init_buffer(&m->rx_buff);
    m->pkt_counter = 0;
}
