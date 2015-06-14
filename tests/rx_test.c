#include "mpudp_monitor.h"

int recv_packet(monitor_t *m)
{
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));

    pthread_mutex_lock(&m->rx_mx);
    while(m->rx_num <= 0)
        pthread_cond_wait(&m->rx_has_data, &m->rx_mx);

    int i;
    for(i = 0; i < BUFF_LEN, i++)
    {
        if(m->last_received+1 == m->rx_data[i]->id)
        {
            // we found a match
            p = m->rx_data[i];
            m->rx_data[i] = NULL;
            m->rx_num--;
            pthread_cond_broadcast(&m->rx_not_full);
        }
    }

    pthread_mutex_unlock(&m->rx_mx);

    realloc(data, p->len);

    memcpy(data, p->payload, p->len);

    return p->len;
}

void dummy_recv(monitor_t *m)
{
    uint8_t *data;
    int res;

    while(res = recv_packet(*m, data))
    {
        printf("I got %d bytes\n", res);
    }
}

int main()
{
    motnitor_t m;
    init_monitor(&m);

    pthread_joint(&m.id, NULL, monitor_thread, &m);

    dummy_recv(&m);

    pthread_join(m.id, NULL);

    return 0;
}
