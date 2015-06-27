#include "mpudp_worker.h"
#include <stdio.h>
#include <stdlib.h>
#include "eth_utils.h"
#include "ip_utils.h"
#include "udp_utils.h"
#include "pcap_utils.h"
#include <pcap.h>
#include <string.h>

void* worker_tx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;

    while(1)
    {
        pthread_mutex_lock(&w->private_tx_buff_mx);
        while(w->private_tx_buff == NULL)
        {
            pthread_cond_wait(&w->tx_ready, &w->private_tx_buff_mx);
        }

        if(w->private_tx_buff->type == MPUDP_CONFIG)
        {
            worker_send(w, w->private_tx_buff, SEND_BCAST);
        }
        else if(w->private_tx_buff->type == MPUDP_DATA)
        {
            worker_send(w, w->private_tx_buff, SEND_UCAST);
            pthread_mutex_lock(&w->wait_ack_buff_mx);

            if(w->wait_ack_buff != w->private_tx_buff)
            {
                w->wait_ack_buff = w->private_tx_buff;
                w->arq_count = 0;
            }
            else
            {
                w->arq_count++;
            }

            gettimeofday(&w->last_send_time, NULL);

            pthread_cond_broadcast(&w->wait_ack_full);
            pthread_mutex_unlock(&w->wait_ack_buff_mx);
        }
        else
        {
            // we are sending ACK
            worker_send(w, w->private_tx_buff, SEND_UCAST);
        }

        /* usleep(w->choke); */

        w->private_tx_buff = NULL;

        pthread_cond_broadcast(&w->tx_empty);
        pthread_cond_broadcast(&m->tx_has_data);
        pthread_mutex_unlock(&w->private_tx_buff_mx);
    }
}

void* worker_rx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));
    mpudp_packet_t *target;

    while(1)
    {
        if(worker_recv_packet(w, p))
        {
            if(p->type == MPUDP_CONFIG)
            {
                mpudp_config_t *config = malloc(sizeof(mpudp_config_t));
                mpudp_chars2config(config, p->payload, p->len);

                pthread_mutex_lock(&w->m->remote_config_mx);
                if(config->id > w->m->remote_config->id)
                {
                    /* printf("[%d] - We have a new config!\n", w->id); */
                    w->m->remote_config = config;

                    pthread_cond_signal(&w->m->remote_config_changed);
                }
                pthread_mutex_unlock(&w->m->remote_config_mx);

            }
            else if(p->type == MPUDP_DATA)
            {
                /* printf("[%d] - got data packet %d!\n", w->id, p->id); */
                pthread_mutex_lock(&w->m->rx_mx);
                while(w->m->rx_num >= BUFF_LEN)
                    pthread_cond_wait(&w->m->rx_not_full, &w->m->rx_mx);

                if((w->m->rx_data[p->id % BUFF_LEN] == NULL) &&
                        (p->id >= w->m->user_expected_id) &&
                        (p->id < w->m->user_expected_id+BUFF_LEN))
                {
                    /* printf("[%d] - accepting new packet %d\n", w->id, p->id); */
                    target = malloc(sizeof(mpudp_packet_t));
                    w->m->rx_data[p->id % BUFF_LEN] = target;

                    *target = *p;
                    target->payload = malloc(sizeof(p->len));
                    memcpy(target->payload, p->payload, p->len);

                    worker_send_ack(w, p->id);
                    w->m->rx_num++;
                }
                else if(p->id < w->m->user_expected_id)
                {
                    // old packet
                    worker_send_ack(w, p->id);
                    /* printf("[%d] - confirming old packet %d\n", w->id, p->id); */
                }
                else
                {
                    // droping packet
                    /* printf("[%d] - droping packet: %d\n", w->id, p->id); */
                }

                pthread_cond_broadcast(&w->m->rx_has_data);
                pthread_mutex_unlock(&w->m->rx_mx);
            }
            else if(p->type == MPUDP_ACK)
            {
                pthread_mutex_lock(&w->wait_ack_buff_mx);
                if(w->wait_ack_buff != NULL && p->id == w->wait_ack_buff->id)
                {
                    w->wait_ack_buff = NULL;
                    pthread_cond_broadcast(&w->m->tx_has_data);
                }
                pthread_mutex_unlock(&w->wait_ack_buff_mx);
            }
        }
    }
}

worker_t* init_worker(int id, char *iface_name, monitor_t *m, float choke)
{
    worker_t *w = malloc(sizeof(worker_t));
    w->m = m;
    w->id = id;
    w->choke = choke*1000000;

    w->private_tx_buff = NULL;

    char *tmp;

    strncpy(w->name, iface_name, 6);

    pcapu_find_dev_by_name(&w->if_desc, iface_name);

    w->src_port = 6666;
    w->dst_port = 8880 + w->id;

    // config src mac
    tmp = pcapu_read_if_mac_s(w->if_desc->name, NULL);
    w->src_mac = malloc(strlen(tmp)+1);
    strcpy(w->src_mac, tmp);

    // config bcast mac
    w->bcast_mac = malloc(MAC_LEN_S);
    strcpy(w->bcast_mac, BCAST_MAC_S);

    // config src ip
    tmp = pcapu_read_if_ip_s(w->if_desc, NULL);
    w->src_ip = malloc(strlen(tmp)+1);
    strcpy(w->src_ip, tmp);

    // config bcast ip
    tmp = pcapu_read_if_bcast_s(w->if_desc, NULL);
    w->bcast_ip = malloc(strlen(tmp)+1);
    strcpy(w->bcast_ip, tmp);

    // alocate space for remote addressess
    w->dst_ip  = malloc(IP_LEN_S_MAX);
    w->dst_mac = malloc(MAC_LEN_S);

    char errbuf[PCAP_ERRBUF_SIZE];

    w->if_handle = pcap_open_live(w->if_desc->name, 1024, 0, 1, errbuf);
    w->state = WORKER_NOT_CONNECTED;

    pthread_mutex_init(&w->config_mx, NULL);
    pthread_mutex_init(&w->private_tx_buff_mx, NULL);
    pthread_mutex_init(&w->wait_ack_buff_mx, NULL);

    pthread_cond_init(&w->tx_empty, NULL);
    pthread_cond_init(&w->tx_ready, NULL);
    pthread_cond_init(&w->wait_ack_full, NULL);

    w->wait_ack_buff = NULL;

    gettimeofday(&w->last_send_time, NULL);

    w->arq_count = 0;

    return w;
}

int spawn_worker(worker_t *w)
{
    pthread_create(&w->tx_thread_id, NULL, &worker_tx_thread, w);
    pthread_create(&w->rx_thread_id, NULL, &worker_rx_thread, w);
    pthread_create(&w->global_tx_watcher_id,NULL,&worker_tx_watcher_thread, w);
    pthread_create(&w->arq_watcher_id, NULL, &worker_arq_watcher, w);
}


void* worker_tx_watcher_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;
    mpudp_packet_t *tmp;

    while(1)
    {
        pthread_mutex_lock(&m->tx_mx);
        while(watchdog_check_state(w))
        {
            pthread_cond_wait(&m->tx_has_data, &m->tx_mx);
        }


        if(m->checkin[w->id] == 1)
        {
            tmp = m->bcast_data;

            m->checkin[w->id] = 0;
            pthread_cond_broadcast(&m->bcast_done);
        }
        else
        {
            pthread_mutex_lock(&w->private_tx_buff_mx);
            pthread_mutex_lock(&w->wait_ack_buff_mx);
            if(w->wait_ack_buff == NULL && w->private_tx_buff == NULL)
            {
                if(m->esc_num != 0)
                {
                    tmp = m->esc_data[m->esc_tail];
                    m->esc_tail = (m->esc_tail + 1) % BUFF_LEN;
                    m->esc_num--;
                    printf("[%d] - gotcha!\n", w->id);
                }
                else
                {
                    tmp = m->tx_data[m->tx_tail];
                    m->tx_num--;
                    m->tx_tail = (m->tx_tail+1) % BUFF_LEN;
                }


                pthread_cond_broadcast(&m->tx_not_full);
            }
            else
            {
                printf("[%d] - waiting for ACK, can't get new data\n", w->id);
            }
            pthread_mutex_unlock(&w->private_tx_buff_mx);
            pthread_mutex_unlock(&w->wait_ack_buff_mx);
        }
        pthread_mutex_unlock(&m->tx_mx);


        if(tmp != NULL)
        {
            // push to private tx buff
            pthread_mutex_lock(&w->private_tx_buff_mx);
            while( w->private_tx_buff != NULL)
            {
                pthread_cond_wait(&w->tx_empty, &w->private_tx_buff_mx);
            }

            /* printf("[%d] - pushed %d to private tx\n", w->id, tmp->id); */

            w->private_tx_buff = tmp;
            tmp = NULL;

            pthread_cond_signal(&w->tx_ready);
            pthread_mutex_unlock(&w->private_tx_buff_mx);
        }
    }
}
int worker_recv_packet(worker_t *w, mpudp_packet_t *p)
{
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    mpudp_packet_t *target;

    int res = pcap_next_ex(w->if_handle, &pkt_header, &pkt_data);

    if(res != 1)
        return 0;

    eth_frame_t frame;
    eth_read_frame(&frame, (u_char*)pkt_data, pkt_header->len);

    if(frame.type[0] != 0x08 || frame.type[1] != 0x00)
    {
        return 0;
    }

    ip_packet_t ip_packet;
    ip_read_packet(&ip_packet, frame.data, frame.data_len);

    if(ip_get_proto(&ip_packet) != PROTO_UDP)
    {
        return 0;
    }

    udp_dgram_t udp_dgram;
    udp_read_dgram(&udp_dgram, ip_packet.payload, ip_get_len(&ip_packet));

    mpudp_chars2packet(p, udp_dgram.data, udp_dgram.len - UDP_PREFIX_LEN);

    if(p->type == MPUDP_DATA || p->type == MPUDP_ACK || p->type == MPUDP_CONFIG)
    {
        return 1;
    }

    return 0;
}

int worker_send(worker_t *w, mpudp_packet_t *p, int type)
{
    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t udp_dgram;

    unsigned char *eth_payload, *ip_payload, *udp_payload;

    /* printf("[%d] - sending packet... %d\n", w->id, p->id); */

    int eth_len, ip_len, udp_len;

    if(type == SEND_UCAST)
    {
        eth_build_frame(&eth_frame, w->dst_mac, w->src_mac, ETH_TYPE_IP);
        ip_build_packet(&ip_packet, w->src_ip, w->dst_ip);
        udp_build_dgram_hdr(&udp_dgram, w->src_port, w->dst_port);
    }
    else if(type == SEND_BCAST)
    {
        eth_build_frame(&eth_frame, w->bcast_mac, w->src_mac, ETH_TYPE_IP);
        ip_build_packet(&ip_packet, w->src_ip, w->bcast_ip);
        udp_build_dgram_hdr(&udp_dgram, w->src_port, w->dst_port);
    }

    uint8_t *payload;
    int len = mpudp_packet2chars(p, &payload);

    udp_set_data(&udp_dgram, payload, len);
    udp_len = udp_dgram2chars(&udp_dgram, &udp_payload);

    ip_set_data(&ip_packet, udp_payload, udp_len);
    ip_len = ip_packet2chars(&ip_packet, &ip_payload);

    eth_set_data(&eth_frame, ip_payload, ip_len);
    eth_len = eth_frame2chars(&eth_frame, &eth_payload);

    pcap_sendpacket(w->if_handle, eth_payload, eth_len);

    return 0;
}

int worker_send_ack(worker_t *w, uint32_t id)
{
    mpudp_packet_t *ack = malloc(sizeof(mpudp_packet_t));
    ack->type = MPUDP_ACK;
    ack->id   = id;
    ack->len  = 0;

    pthread_mutex_lock(&w->private_tx_buff_mx);
    while(w->private_tx_buff != NULL)
    {
        pthread_cond_wait(&w->tx_empty, &w->private_tx_buff_mx);
    }

    /* printf("[%d] - pushing ack %d\n", w->id, id); */
    w->private_tx_buff = ack;

    pthread_cond_broadcast(&w->tx_ready);
    pthread_mutex_unlock(&w->private_tx_buff_mx);

    return 0;
}

int watchdog_check_state(worker_t *w)
{
    pthread_mutex_lock(&w->private_tx_buff_mx);
    pthread_mutex_lock(&w->wait_ack_buff_mx);

    int users_data = (w->m->tx_num <= 0) && (w->m->esc_num <= 0);
    int worker_state = w->state == WORKER_NOT_CONNECTED;
    users_data |= worker_state;

    int tx_transaction = w->private_tx_buff != NULL || w->wait_ack_buff != NULL;

    int bcast_data = w->m->checkin[w->id] == 0;

    pthread_mutex_unlock(&w->private_tx_buff_mx);
    pthread_mutex_unlock(&w->wait_ack_buff_mx);

    /* printf("[%d] - watcher state: users_data %d - transaction %d - bcast-data %d\n", */
    /*         w->id, users_data, tx_transaction, bcast_data); */
    /* printf("[%d] - tx num %d - worker state - %d\n", w->id, w->m->tx_num, w->state); */

    return (users_data || tx_transaction) && bcast_data;
}

void* worker_arq_watcher(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;

    struct timeval current_time;
    unsigned long seconds, useconds, difftime;

    while(1)
    {
        /* printf("[%d] - ARQ alive, arq buff %p\n", w->id, w->wait_ack_buff); */
        pthread_mutex_lock(&w->wait_ack_buff_mx);
        while(w->wait_ack_buff == NULL)
        {
            pthread_cond_wait(&w->wait_ack_full, &w->wait_ack_buff_mx);
        }
        pthread_mutex_unlock(&w->wait_ack_buff_mx);

        gettimeofday(&current_time, NULL);
        seconds  = current_time.tv_sec  - w->last_send_time.tv_sec;
        useconds = current_time.tv_usec - w->last_send_time.tv_usec;
        difftime = seconds*1000 + useconds/1000;

        if(difftime > 100)
        {
            printf("[%d] - should retransmit ", w->id);
            printf("packet %d for %d time\n", w->wait_ack_buff->id, w->arq_count);

            if(w->arq_count > 10)
            {
                printf("[%d] - link is dead!\n", w->id);
                pthread_mutex_lock(&m->tx_mx);

                m->esc_data[m->esc_head] = w->wait_ack_buff;
                m->esc_head = (m->esc_head + 1) % BUFF_LEN;
                m->esc_num++;

                w->state = WORKER_NOT_CONNECTED;
                w->wait_ack_buff = NULL;

                pthread_cond_broadcast(&m->bcast_done);
                pthread_cond_broadcast(&m->tx_has_data);
                pthread_mutex_unlock(&m->tx_mx);
            }

            pthread_mutex_lock(&w->private_tx_buff_mx);
            while(w->private_tx_buff != NULL)
            {
                pthread_cond_wait(&w->tx_empty, &w->private_tx_buff_mx);
            }

            w->private_tx_buff = w->wait_ack_buff;
            pthread_cond_broadcast(&w->tx_ready);
            pthread_mutex_unlock(&w->private_tx_buff_mx);
        }


        usleep(25000);
    }
}
