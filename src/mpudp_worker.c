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
    mpudp_packet_t *tmp; // worker's tx buffer

    while(1)
    {
        pthread_mutex_lock(&w->config_mx);
        pthread_mutex_lock(&m->tx_mx);

        while(m->tx_num <= 0 && m->checkin[w->id] == 0)
        {
            pthread_cond_wait(&m->tx_has_data, &m->tx_mx);
        }

        if(m->checkin[w->id] == 1)
        {
            printf("[%2d] - It's broadcast!\n", w->id);
            m->checkin[w->id] = 0;

            tmp = m->bcast_data;

            pthread_mutex_unlock(&w->config_mx);
            pthread_mutex_unlock(&m->tx_mx);
            pthread_cond_broadcast(&m->bcast_done);

            worker_send_bcast(w, tmp);
            usleep(w->choke);
        }
        else if(w->state == WORKER_CONNECTED)
        {
            int id = m->tx_data[m->tx_tail]->id;

            tmp = m->tx_data[m->tx_tail];

            m->tx_num--;
            m->tx_tail =  (m->tx_tail + 1) % BUFF_LEN;

            pthread_mutex_unlock(&w->config_mx);
            pthread_mutex_unlock(&m->tx_mx);
            pthread_cond_signal(&m->tx_not_full);

            usleep(w->choke);

            worker_send_packet(w, tmp);
            free(tmp);

            printf("Worker %d got it! Sending: %3d ", w->id, id);
            printf("tail: %3d, head: %3d num: %3d\n", m->tx_tail, m->tx_head, m->tx_num);
        }
        else
        {
            pthread_mutex_unlock(&w->config_mx);
            pthread_mutex_unlock(&m->tx_mx);
        }

    }
}

void* worker_rx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;
    mpudp_packet_t *tmp = malloc(sizeof(mpudp_packet_t));


    while(1)
    {
        if(worker_recv_packet(w, tmp))
        {
            printf("[%2d] - Got the packet.\n", w->id);

            // decode packet
            // if it's config, push new config to the monitor
            // if it's data, push to user rx buffer
            // if it's ACK, notify your tx thread
        }
        else
        {
            puts("No data... :(");
        }
    }

}

worker_t* init_worker(int id, char *iface_name, monitor_t *m, float choke)
{
    worker_t *w = malloc(sizeof(worker_t));
    init_buffer(&w->tx_buff);
    w->m = m;
    w->id = id;
    w->choke = choke*1000000;

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

    return w;
}

int spawn_worker(worker_t *w)
{
    pthread_create(&w->tx_thread_id, NULL, &worker_tx_thread, w);
    pthread_create(&w->rx_thread_id, NULL, &worker_rx_thread, w);
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

    char mac[MAC_LEN_S];
    puts(chars2mac(frame.dst, mac));
    puts(w->dst_mac);

    if(memcmp(frame.dst, BCAST_MAC_B, MAC_LEN) == 0)
    {
        printf("[%2d] - We got a broadcast!\n", w->id);

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
                puts("We have a new config!");
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
        puts("The frame is for us...");
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
    }

    return 0;
}

int worker_send_packet(worker_t *w, mpudp_packet_t *p)
{
    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t udp_dgram;

    unsigned char *eth_payload, *ip_payload, *udp_payload;

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

    /* printf("UDP: %d\n", udp_len); */
    /* printf("IP : %d\n", ip_len); */
    /* printf("ETH: %d\n", eth_len); */

    pcap_sendpacket(w->if_handle, eth_payload, eth_len);

    return 0;
}

int worker_send_bcast(worker_t *w, mpudp_packet_t *p)
{
    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t udp_dgram;

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

    /* printf("UDP: %d\n", udp_len); */
    /* printf("IP : %d\n", ip_len); */
    /* printf("ETH: %d\n", eth_len); */

    pcap_sendpacket(w->if_handle, eth_payload, eth_len);

    return 0;
}
