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
            worker_send_bcast(w, w->private_tx_buff);
        }
        else
        {
            worker_send_packet(w, w->private_tx_buff);
            pthread_mutex_lock(&w->wait_ack_buff_mx);
            w->wait_ack_buff = w->private_tx_buff;
            /* printf("[%d] - tx thread changed ack waiting buff state to %p\n", w->id, w->wait_ack_buff); */
            /* w->wait_ack_buff = NULL; */
            pthread_mutex_unlock(&w->wait_ack_buff_mx);
        }
        usleep(w->choke);

        w->private_tx_buff = NULL;

        pthread_mutex_unlock(&w->private_tx_buff_mx);
        pthread_cond_signal(&w->tx_empty);
    }
}

void* worker_rx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));

    while(1)
    {
        if(worker_recv_packet(w, p))
        {
            /* printf("[%d] - Got the packet\n", w->id); */
        }
        else
        {
            /* printf("[%d] - No data... :(\n", w->id); */
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

    w->if_handle = pcap_open_live(w->if_desc->name, 1024, 0, 1000, errbuf);
    w->state = WORKER_NOT_CONNECTED;

    pthread_mutex_init(&w->config_mx, NULL);
    pthread_mutex_init(&w->private_tx_buff_mx, NULL);
    pthread_mutex_init(&w->wait_ack_buff_mx, NULL);

    pthread_cond_init(&w->tx_empty, NULL);
    pthread_cond_init(&w->tx_ready, NULL);

    w->wait_ack_buff = NULL;

    return w;
}

int spawn_worker(worker_t *w)
{
    pthread_create(&w->tx_thread_id, NULL, &worker_tx_thread, w);
    pthread_create(&w->rx_thread_id, NULL, &worker_rx_thread, w);
    pthread_create(&w->global_tx_watcher_id,NULL,&worker_tx_watcher_thread, w);
}


void* worker_tx_watcher_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;
    mpudp_packet_t *tmp;

    while(1)
    {
        // fetch to tmp
        pthread_mutex_lock(&m->tx_mx);
        /* while( (m->tx_num <= 0 || w->state == WORKER_NOT_CONNECTED) && m->checkin[w->id] == 0) */
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
                tmp = m->tx_data[m->tx_tail];

                printf("[%d] - we can get new user's data %d\n", w->id, tmp->id);


                m->tx_num--;
                m->tx_tail = (m->tx_tail+1) % BUFF_LEN;

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

            printf("[%d] - pushed %d to private tx\n", w->id, tmp->id);

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

    int res = pcap_next_ex(w->if_handle, &pkt_header, &pkt_data);

    if(res != 1)
        return 0;

    eth_frame_t frame;
    eth_read_frame(&frame, (u_char*)pkt_data, pkt_header->len);

    if(frame.type[0] != 0x08 || frame.type[1] != 0x00)
    {
        return 0;
    }

    /* printf("[%d] - frame type %2hhX %2hhX\n", w->id, frame.type[0], frame.type[1]); */

    char mac[MAC_LEN_S];
    chars2mac(frame.dst, mac);

    if(memcmp(frame.dst, BCAST_MAC_B, MAC_LEN) == 0)
    {
        printf("[%d] - We got a broadcast!\n", w->id);

        ip_packet_t ip_packet;
        ip_read_packet(&ip_packet, frame.data, frame.data_len);

        udp_dgram_t udp_dgram;
        udp_read_dgram(&udp_dgram, ip_packet.payload, ip_get_len(&ip_packet));

        mpudp_chars2packet(p, udp_dgram.data, udp_dgram.len - UDP_PREFIX_LEN);

        if(p->type == MPUDP_CONFIG)
        {
            mpudp_config_t *config = malloc(sizeof(mpudp_config_t));
            mpudp_chars2config(config, p->payload, p->len);

            pthread_mutex_lock(&w->m->remote_config_mx);
            if(config->id > w->m->remote_config->id)
            {
                printf("[%d] - We have a new config!\n", w->id);
                w->m->remote_config = config;

                pthread_mutex_unlock(&w->m->remote_config_mx);
                pthread_cond_signal(&w->m->remote_config_changed);
            }
            else
            {
                pthread_mutex_unlock(&w->m->remote_config_mx);
            }

        }

    }
    else if(strncmp(mac, w->src_mac, MAC_LEN_S) == 0)
    {
        // continue decoding ip_packet and mpudp_packet
        // if packet is ACK, check our buffer, confirm ACK
        // and remove that packet from ACK waiting list
        // if ACK is not for our packet, just drop it
        // other variant is that this is user data
        // if it's user data, push ACK packet to the TX buffer
        // and accept this packet (push it to user's RX buffer)
        // and notify user that there is new data available
        // Does this mean that we really need a tx buffer for this worker?
        // Is there any possibility that we got a packet on another iface?

        /* printf("[%d] - The frame is for us %hhu...\n", w->id, frame.type[1]); */
        ip_packet_t ip_packet;
        ip_read_packet(&ip_packet, frame.data, frame.data_len);

        if(ip_get_proto(&ip_packet) != PROTO_UDP)
        {
            /* printf("[%d] - ip proto: %2hhX\n", w->id, ip_get_proto(&ip_packet)); */
            /* printf("[%d] - not udp packet, dropping...\n", w->id); */
            return 0;
        }

        udp_dgram_t udp_dgram;
        udp_read_dgram(&udp_dgram, ip_packet.payload, ip_get_len(&ip_packet));

        mpudp_chars2packet(p, udp_dgram.data, udp_dgram.len - UDP_PREFIX_LEN);

        if(p->type == MPUDP_DATA)
        {
            /* printf("[%d] - We got data and should send ACK\n", w->id); */

            worker_send_ack(w, p->id);
        }
        else if(p->type == MPUDP_ACK)
        {
            printf("[%d] - got ACK %d, should empty ack waiting and notify tx\n", w->id, p->id);
        }
    }

    return 0;
}

int worker_send_packet(worker_t *w, mpudp_packet_t *p)
{
    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t udp_dgram;

    unsigned char *eth_payload, *ip_payload, *udp_payload;

    printf("[%d] - sending packet...\n", w->id);

    int eth_len, ip_len, udp_len;

    eth_build_frame(&eth_frame, w->dst_mac, w->src_mac, ETH_TYPE_IP);
    ip_build_packet(&ip_packet, w->src_ip, w->dst_ip);
    udp_build_dgram_hdr(&udp_dgram, w->src_port, w->dst_port);

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

int worker_send_bcast(worker_t *w, mpudp_packet_t *p)
{
    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t udp_dgram;

    printf("[%d] - sending bcast...\n", w->id);

    unsigned char *eth_payload, *ip_payload, *udp_payload;

    int eth_len, ip_len, udp_len;

    eth_build_frame(&eth_frame, w->bcast_mac, w->src_mac, ETH_TYPE_IP);
    ip_build_packet(&ip_packet, w->src_ip, w->bcast_ip);
    udp_build_dgram_hdr(&udp_dgram, w->src_port, w->dst_port);

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

int worker_send_ack(worker_t *w, int8_t id)
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

    printf("[%d] - pushing ack %d\n", w->id, id);
    w->private_tx_buff = ack;

    pthread_mutex_unlock(&w->private_tx_buff_mx);
    pthread_cond_broadcast(&w->tx_ready);

    return 0;
}

int watchdog_check_state(worker_t *w)
{
    pthread_mutex_lock(&w->private_tx_buff_mx);
    pthread_mutex_lock(&w->wait_ack_buff_mx);
    int users_data = w->m->tx_num <= 0 || w->state == WORKER_NOT_CONNECTED || w->wait_ack_buff != NULL;
    int bcast_data = w->m->checkin[w->id] == 0;
    int tx_transaction = w->private_tx_buff != NULL;
    pthread_mutex_unlock(&w->private_tx_buff_mx);
    pthread_mutex_unlock(&w->wait_ack_buff_mx);

    printf("[%d] - watcher state: users_data %d - bcast-data %d\n", w->id, users_data, bcast_data);

    return users_data && bcast_data;
}
