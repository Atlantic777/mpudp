#include "mpudp_monitor.h"
#include "mpudp_worker.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void* monitor_thread(void *arg)
{
    monitor_t *m = (monitor_t*)arg;
    int i;

    char **iface_names_list;
    int num_ifaces = pcapu_find_all_devs(&iface_names_list);

    m->workers = malloc(sizeof(worker_t*)*num_ifaces);

    for(i = 0; i < num_ifaces; i++)
        m->workers[i] = init_worker(i, iface_names_list[i], m, 0.5*i+1);

    m->num_workers = num_ifaces;
    m->checkin = malloc(sizeof(int)*m->num_workers);

    for(i = 0; i < num_ifaces; i++)
        m->checkin[i] = 0;

    for(i = 0; i < num_ifaces; i++)
        spawn_worker(m->workers[i]);

    // spawn config monitoring threads
    pthread_create(&m->config_announcer_id, NULL, monitor_config_announcer, m);
    pthread_create(&m->config_receiver_id, NULL, monitor_config_receiver, m);

    // move this to the config thread

    for(i = 0; i < num_ifaces; i++)
        pthread_join(m->workers[i]->tx_thread_id, NULL);
        pthread_join(m->workers[i]->rx_thread_id, NULL);
        pthread_join(m->workers[i]->global_tx_watcher_id, NULL);

    pthread_join(m->config_announcer_id, NULL);
    pthread_join(m->config_receiver_id, NULL);
}

void* monitor_config_announcer(void *arg)
{
    monitor_t *m = (monitor_t*)arg;


    mpudp_config_t config;
    mpudp_build_config(m, &config);
    uint8_t *payload;

    mpudp_packet_t *bcast_packet;
    int len = mpudp_config2chars(&config, &payload);
    mpudp_prepare_packet(&bcast_packet, payload, len);

    bcast_packet->type = MPUDP_CONFIG;

    while(1)
    {
        bcast_push(m, bcast_packet);
        sleep(2);
    }

}

void* monitor_config_receiver(void *arg)
{
    monitor_t *m = (monitor_t*)arg;

    int last_config_id = m->remote_config->id;

    while(1)
    {
        pthread_mutex_lock(&m->remote_config_mx);
        while(m->remote_config->id == last_config_id)
        {
            pthread_cond_wait(&m->remote_config_changed, &m->remote_config_mx);
        }

        puts("Config really changed!");
        last_config_id = m->remote_config->id;
        pthread_mutex_unlock(&m->remote_config_mx);

        // do the matching
        int i;
        for(i = 0; i < 2; i++)
        {
            // stop workers
            pthread_mutex_lock(&m->workers[i]->config_mx);

            // change their configs
            chars2ip(m->remote_config->if_list[i].ip, m->workers[i]->dst_ip);
            chars2mac(m->remote_config->if_list[i].mac, m->workers[i]->dst_mac);
            m->workers[i]->dst_port = m->remote_config->if_list[i].port;
            m->workers[i]->state = WORKER_CONNECTED;

            // release workers
            pthread_mutex_unlock(&m->workers[i]->config_mx);
        }

        pthread_cond_broadcast(&m->tx_has_data);
    }

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
    m->rx_num  = 0;
    m->user_expected_id = 0;
    pthread_mutex_init(&m->rx_mx, NULL);

    // init esc_buffer
    m->esc_head = 0;
    m->esc_tail = 0;
    m->esc_num  = 0;
    pthread_mutex_init(&m->esc_mx, NULL);

    int i;
    for(i = 0; i < BUFF_LEN; i++)
        m->rx_data[i] = NULL;

    // init bcast buffer
    pthread_mutex_init(&m->local_config_mx, NULL);
    pthread_mutex_init(&m->remote_config_mx, NULL);

    // common conditional vars
    pthread_cond_init(&m->tx_has_data, NULL);
    pthread_cond_init(&m->tx_not_full, NULL);

    pthread_cond_init(&m->rx_has_data, NULL);
    pthread_cond_init(&m->rx_not_full, NULL);

    pthread_cond_init(&m->bcast_done, NULL);

    pthread_cond_init(&m->local_config_changed, NULL);
    pthread_cond_init(&m->remote_config_changed, NULL);

    // config handles
    m->local_config = malloc(sizeof(mpudp_config_t));

    m->remote_config = malloc(sizeof(mpudp_config_t));
    m->remote_config->id = -1;

    // monitor specific
    m->pkt_counter = 0;
    m->num_workers = 0;
}

int bcast_empty(monitor_t *m)
{
    int sum = 0;

    int i;
    for(i = 0; i < m->num_workers; i++)
        sum += m->checkin[i];

    return sum == 0;
}

void bcast_push(monitor_t *m, mpudp_packet_t *p)
{
    /* pthread_mutex_lock(&m->bcast_mx); */
    pthread_mutex_lock(&m->tx_mx);
    while(bcast_empty(m) == 0)
    {
        /* pthread_cond_wait(&m->bcast_done, &m->bcast_mx); */
        pthread_cond_wait(&m->bcast_done, &m->tx_mx);
    }

    int i;
    for(i = 0; i < m->num_workers; i++)
        m->checkin[i] = 1;

    m->bcast_data = p;

    /* pthread_mutex_unlock(&m->bcast_mx); */
    pthread_cond_broadcast(&m->tx_has_data);
    pthread_mutex_unlock(&m->tx_mx);
}
