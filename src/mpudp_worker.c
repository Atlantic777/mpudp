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
        pthread_mutex_lock(&m->tx_mx);

        while(m->tx_num <= 0 && m->checkin[w->id] == 0)
        {
            pthread_cond_wait(&m->tx_has_data, &m->tx_mx);
        }

        if(m->checkin[w->id] == 1)
        {
            printf("It's broadcast! %d\n", w->id);
            m->checkin[w->id] = 0;

            pthread_mutex_unlock(&m->tx_mx);
            pthread_cond_broadcast(&m->bcast_done);
        }
        else
        {
            int id = m->tx_data[m->tx_tail]->id;

            tmp = m->tx_data[m->tx_tail];

            m->tx_num--;
            m->tx_tail =  (m->tx_tail + 1) % BUFF_LEN;

            pthread_mutex_unlock(&m->tx_mx);
            pthread_cond_signal(&m->tx_not_full);

            usleep(w->choke);

            worker_send_packet(w, tmp);
            free(tmp);

            printf("Worker %d got it! Sending: %3d ", w->id, id);
            printf("tail: %3d, head: %3d num: %3d\n", m->tx_tail, m->tx_head, m->tx_num);
        }
    }
}

void* worker_rx_thread(void *arg)
{
    /* worker_t *w = (worker_t*)arg; */
    /* mpudp_buff_t *buff = &w->m->rx_buff; */

}

worker_t* init_worker(int id, char *iface_name, monitor_t *m, float choke)
{
    worker_t *w = malloc(sizeof(worker_t));
    init_buffer(&w->tx_buff);
    w->m = m;
    w->id = id;
    w->choke = choke*1000000;

    char *tmp;

    pcapu_find_dev_by_name(&w->if_desc, iface_name);

    w->src_port = 6666;
    tmp = pcapu_read_if_mac_s(w->if_desc->name, NULL);
    w->src_mac = malloc(strlen(tmp)+1);
    strcpy(w->src_mac, tmp);

    tmp = pcapu_read_if_ip_s(w->if_desc, NULL);
    w->src_ip = malloc(strlen(tmp)+1);
    strcpy(w->src_ip, tmp);

    char errbuf[PCAP_ERRBUF_SIZE];

    w->if_handle = pcap_open_live(w->if_desc->name, 1024, 1, 1000, errbuf);

    return w;
}

int spawn_worker(worker_t *w)
{
    pthread_create(&w->tx_thread_id, NULL, &worker_tx_thread, w);
    pthread_create(&w->rx_thread_id, NULL, &worker_rx_thread, w);
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

    udp_set_data(&udp_dgram, p->payload, p->len);
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
