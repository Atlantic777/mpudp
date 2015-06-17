#include <stdio.h>
#include <pthread.h>
#include "mpudp_monitor.h"
#include "mpudp_utils.h"
#include <stdlib.h>
#include <string.h>

void send_packet(uint8_t *data, int len, monitor_t *m)
{
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));
    p->payload = malloc(sizeof(len));
    p->len = len;

    pthread_mutex_lock(&m->tx_mx);

    while(m->tx_num >= BUFF_LEN)
        pthread_cond_wait(&m->tx_not_full, &m->tx_mx);


    p->id = m->pkt_counter++;
    p->type = MPUDP_DATA;

    m->tx_data[m->tx_head] = p;
    m->tx_num++;
    m->tx_head = (m->tx_head+1) % BUFF_LEN;

    pthread_cond_broadcast(&m->tx_has_data);
    pthread_mutex_unlock(&m->tx_mx);
}

void dummy_send(monitor_t *m)
{
    int i;
    uint8_t data[] = "Hello world!\n";

    for(i = 0; i < 1000; i++)
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
