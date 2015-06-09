#include <stdio.h>
#include <pthread.h>
#include "mpudp_monitor.h"
#include "mpudp_utils.h"
#include <stdlib.h>
#include <string.h>

void send_packet(uint8_t *data, int len, monitor_t *m)
{
    /* mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));; */
    /* p->payload = malloc(sizeof(len)); */
    /* p->len     = len; */
    /* memcpy(p->payload, data, len); */
    /*  */
    /* mpudp_buff_t *buff = &m->tx_buff; */
    /*  */
    /* pthread_mutex_lock(&buff->mx); */
    /* while(buff->num >= BUFF_LEN) */
    /*     pthread_cond_wait(&buff->full, &buff->mx); */
    /*  */
    /* p->id = m->pkt_counter++; */
    /*  */
    /* buff->data[buff->head] = p; */
    /* buff->num++; */
    /* buff->head = (buff->head+1) % BUFF_LEN; */
    /*  */
    /* pthread_mutex_unlock(&buff->mx); */
    /*  */
    /* pthread_cond_broadcast(&buff->empty); */

    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));
    p->payload = malloc(sizeof(len));
    p->len = len;

    pthread_mutex_lock(&m->tx_mx);

    while(m->tx_num >= BUFF_LEN)
        pthread_cond_wait(&m->tx_not_full, &m->tx_mx);


    p->id = m->pkt_counter++;

    m->tx_data[m->tx_head] = p;
    m->tx_num++;
    m->tx_head = (m->tx_head+1) % BUFF_LEN;

    pthread_mutex_unlock(&m->tx_mx);

    pthread_cond_broadcast(&m->tx_has_data);
}

void fill_rx_buffer(monitor_t *m)
{
    /* mpudp_buff_t *buff = &m->rx_buff; */
    /*  */
}

int receive_packet(mpudp_packet_t *p, monitor_t *m)
{

}

void dummy_send(monitor_t *m)
{
    int i;
    uint8_t data[] = "Hello world!\n";

    for(i = 0; i < 20; i++)
        send_packet(data, strlen(data), m);

    puts("user finished sending");
}

int main()
{
    monitor_t m;
    init_monitor(&m);

    pthread_create(&m.id, NULL, monitor_thread, &m);

    dummy_send(&m);

    pthread_join(m.id, NULL);
    return 0;
}
