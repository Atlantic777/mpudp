#include "mpudp_monitor.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void dummy_recv(monitor_t *m)
{
    uint8_t *data;

    int i, len;
    for(i = 0; i < 1000; i++)
    {
        len = mpudp_recv_packet(m, &data);

        /* if((i % 15) == 0) */
        /*     usleep(100000); */

        printf("Got packet %d with %d bytes: %s\n", i, len, data);
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
