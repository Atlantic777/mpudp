#include "mpudp_monitor.h"
#include <pthread.h>
#include <stdio.h>

int recv(monitor_t *m, uint8_t *data)
{
    return 0;
}

void dummy_recv(monitor_t *m)
{
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
