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
    {
        m->workers[i] = init_worker(i, iface_names_list[i], m, 0.5*i+1);
    }


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

    char **iface_names_list;
    mpudp_config_t *config = malloc(sizeof(mpudp_config_t));
    config->id = -1;

    uint8_t *payload;

    mpudp_packet_t *bcast_packet;

    while(1)
    {
        int num_ifaces = pcapu_find_all_devs(&iface_names_list);
        mpudp_build_config(num_ifaces, iface_names_list, config);

        /* puts("Config announcer woke up!"); */

        if(mpudp_config_different(m->local_config, config))
        {
            config->id = m->local_config->id + 1;
            m->local_config = config;
            config = malloc(sizeof(mpudp_config_t));
            printf("We have new local config: %d\n", m->local_config->id);

            mpudp_print_config(m->local_config);

            reconfigure_workers(m);
        }

        int len = mpudp_config2chars(m->local_config, &payload);
        mpudp_prepare_packet(&bcast_packet, payload, len);
        bcast_packet->type = MPUDP_CONFIG;

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
        while(m->remote_config->id <= last_config_id)
        {
            pthread_cond_wait(&m->remote_config_changed, &m->remote_config_mx);
        }

        puts("Config really changed!");
        last_config_id = m->remote_config->id;
        pthread_mutex_unlock(&m->remote_config_mx);

        mpudp_print_config(m->remote_config);

        /* match_workers(m); */
        reconfigure_workers(m);
    }

}

void match_workers(monitor_t *m)
{
    int i, j;
    uint32_t src_mask, dst_mask;

    for(i = 0; i < m->local_config->num_if; i++)
    {
        pthread_mutex_lock(&m->workers[i]->config_mx);

        src_mask = m->local_config->if_list[i].ip & ~0xFF;

        for(j = 0; j < m->remote_config->num_if; j++)
        {
            dst_mask = m->remote_config->if_list[j].ip & ~0xFF;

            if(src_mask == dst_mask)
            {
                printf("found a match! %hhu - %hhu\n", src_mask >> 8, dst_mask >> 8);
                chars2ip(m->remote_config->if_list[j].ip, m->workers[i]->dst_ip);
                chars2mac(m->remote_config->if_list[j].mac, m->workers[i]->dst_mac);
                m->workers[i]->dst_port = m->remote_config->if_list[j].port;
                m->workers[i]->state = WORKER_CONNECTED;
                m->workers[i]->if_handle = pcap_open_live(m->workers[i]->if_desc->name, 2000, 0, 5,
                        m->workers[i]->errbuf);
                break;
            }
            else
            {
                m->workers[i]->state = WORKER_NOT_CONNECTED;
            }
        }
        pthread_mutex_unlock(&m->workers[i]->config_mx);
    }

    pthread_cond_broadcast(&m->tx_has_data);
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
    for(i = 0; i < BUFF_LEN*2; i++)
        m->esc_data[i] = NULL;


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
    m->local_config->id = -1;
    m->local_config->num_if = 0;

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

void reconfigure_workers(monitor_t *m)
{
    worker_t *w[2], *nw = NULL;
    mpudp_packet_t *tmp;

    // stop workers
    int i;
    for(i = 0; i < m->num_workers; i++)
    {
        printf("Shutting down: %d\n", i);
        m->workers[i]->state = WORKER_NOT_CONNECTED;
        w[i] = m->workers[i];
    }

    // fill escape buffer
    pthread_mutex_lock(&m->workers[0]->wait_ack_buff_mx);
    pthread_mutex_lock(&m->workers[1]->wait_ack_buff_mx);
    pthread_mutex_lock(&m->esc_mx);

    int last_id = 0;

    printf("First %d Second %d\n", w[0]->ack_num, w[1]->ack_num);
    for(i = 0; i < BUFF_LEN*2; i++)
    {
        if(w[0]->wait_ack_buff[w[0]->ack_tail] == NULL)
        {
            w[0]->ack_tail = (w[0]->ack_tail + 1) % BUFF_LEN;
            continue;
        }

        if(w[1]->wait_ack_buff[w[1]->ack_tail] == NULL)
        {
            w[1]->ack_tail = (w[1]->ack_tail + 1) % BUFF_LEN;
            continue;
        }

        // set tmp pointer
        if(w[0]->wait_ack_buff[w[0]->ack_tail]->id < w[1]->wait_ack_buff[w[1]->ack_tail]->id)
        {
            printf("%d %3d -: %d\n", w[0]->id, w[0]->ack_tail, w[0]->wait_ack_buff[w[0]->ack_tail]->id);

            tmp = w[0]->wait_ack_buff[w[0]->ack_tail];

            w[0]->wait_ack_buff[w[0]->ack_tail] = NULL;
            w[0]->arq_count[w[0]->ack_tail] = 0;
            w[0]->ack_tail = (w[0]->ack_tail + 1) % BUFF_LEN;
            w[0]->ack_num--;
        }
        else
        {
            printf("%d %3d -: %d\n", w[1]->id, w[1]->ack_tail, w[1]->wait_ack_buff[w[1]->ack_tail]->id);

            tmp = w[1]->wait_ack_buff[w[1]->ack_tail];

            w[1]->wait_ack_buff[w[1]->ack_tail] = NULL;
            w[1]->arq_count[w[1]->ack_tail] = 0;
            w[1]->ack_tail = (w[1]->ack_tail + 1) % BUFF_LEN;
            w[1]->ack_num--;
        }

        // push it actually to esc buffer
        if(tmp != NULL)
        {
            m->esc_data[m->esc_head] = tmp;
            m->esc_head = (m->esc_head + 1) % (BUFF_LEN*2);
            m->esc_num++;
        }

        // make tmp pointer null again
        tmp = NULL;

        if(w[0]->ack_num == 0)
        {
            nw = w[1];
            break;
        }
        if(w[1]->ack_num == 0)
        {
            nw = w[0];
            break;
        }
    }

    if(nw == NULL && w[0]->wait_ack_buff[w[0]->ack_tail])
    {
        nw = w[0];
        printf("One empty, go on with another! %d, choice %d %d\n", i, nw->id, nw->ack_num);
    }
    else if(nw == NULL && w[1]->wait_ack_buff[w[1]->ack_tail])
    {
        nw = w[1];
        printf("One empty, go on with another! %d, choice %d %d\n", i, nw->id, nw->ack_num);
    }

    while(nw != NULL && nw->ack_num)
    {
        if(nw->wait_ack_buff[nw->ack_tail] != NULL)
        {
            printf("Escaping: %d\n", nw->wait_ack_buff[nw->ack_tail]->id);

            m->esc_data[m->esc_head] = nw->wait_ack_buff[nw->ack_tail];
            m->esc_head = (m->esc_head + 1) % (BUFF_LEN*2);
            m->esc_num++;

        }

        nw->wait_ack_buff[nw->ack_tail] = NULL;
        nw->arq_count[nw->ack_tail] = 0;
        nw->ack_tail = (nw->ack_tail + 1) % BUFF_LEN;
        nw->ack_num--;
    }

    w[0]->ack_head = 0;
    w[0]->ack_tail = 0;
    w[0]->ack_num  = 0;

    w[1]->ack_tail = 0;
    w[1]->ack_head = 0;
    w[1]->ack_num  = 0;

    pthread_mutex_unlock(&m->workers[0]->wait_ack_buff_mx);
    pthread_mutex_unlock(&m->workers[1]->wait_ack_buff_mx);
    pthread_mutex_unlock(&m->esc_mx);


    // restart workers
    match_workers(m);
    puts("workers matched");
}
