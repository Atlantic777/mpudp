#include <stdio.h>
#include <pthread.h>
#include "mpudp_monitor.h"
#include "mpudp_utils.h"
#include <stdlib.h>
#include <string.h>

void dummy_send(monitor_t *m)
{
    int i;
    uint8_t data[] = "Hello world!\n";

    for(i = 0; i < 1000; i++)
        mpudp_send_packet(m, data, strlen(data));

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
