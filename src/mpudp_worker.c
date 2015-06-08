#include "mpudp_worker.h"
#include <stdio.h>
#include <stdlib.h>
#include "eth_utils.h"
#include "ip_utils.h"
#include "udp_utils.h"

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

int worker_send_packet(worker_t *w, mpudp_packet_t *p)
{
    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t udp_dgram;

    unsigned char *eth_payload, *ip_payload, *udp_payload;

    int eth_len, ip_len, udp_len;

    eth_compile_frame(&eth_frame, w->dst_mac, w->src_mac, ETH_TYPE_IP);
    ip_build_packet(&ip_packet, w->src_ip, w->dst_ip);
    udp_build_dgram_hdr(&udp_dgram, w->src_port, w->dst_port);

    udp_set_data(&udp_dgram, p->payload, p->len);
    udp_len = udp_dgram2chars(&udp_dgram, &udp_payload);

    ip_set_data(&ip_packet, udp_payload, udp_len);
    ip_len = ip_packet2chars(&ip_packet, &ip_payload);

    eth_set_data(&eth_frame, ip_payload, ip_len);
    eth_len = ip_frame2chars(&eth_frame, &eth_payload);

    pcap_send_packet(w->if_handle, eth_payload, eth_len);

    return 0;
}
