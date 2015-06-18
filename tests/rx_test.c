#include "mpudp_monitor.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

int next_packet_available(monitor_t *m)
{
    printf("\n\nExpecting: %d\n", m->user_expected_id);

    int id = -1, i;
    for(i = 0; i < BUFF_LEN; i++)
    {
        if(m->rx_data[i] != NULL)
        {
            if(m->rx_data[i]->id == m->user_expected_id)
            {
                printf("%d - %p: ", i, m->rx_data[i]);
                printf("%d ", m->rx_data[i]->id);
                printf("MATCHING!");
                printf("\n");
                id = i;
            }
        }
    }

    return id;
}

int recv(monitor_t *m, uint8_t *data)
{
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));
    int id;

    pthread_mutex_lock(&m->rx_mx);
    while((id = next_packet_available(m)) == -1)
        pthread_cond_wait(&m->rx_has_data, &m->rx_mx);

    p = m->rx_data[id % BUFF_LEN];
    m->rx_data[id % BUFF_LEN] = NULL;

    printf("rx buff num state: %d, packet id %d\n", m->rx_num, p->id);

    m->rx_num--;
    m->user_expected_id++;

    pthread_cond_broadcast(&m->rx_not_full);
    pthread_mutex_unlock(&m->rx_mx);
    return 0;
}

void dummy_recv(monitor_t *m)
{
    int i;
    for(i = 0; i < 1000; i++)
    {
        recv(m, NULL);

        if((i % 15) == 0)
            usleep(100000);
    }
}

int main()
{
    monitor_t m;
    init_monitor(&m);

    pthread_create(&m.id, NULL, monitor_thread, &m);

    dummy_recv(&m);

    pthread_join(m.id, NULL);

    return 0;
}
