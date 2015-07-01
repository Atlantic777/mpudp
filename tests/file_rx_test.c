#include "mpudp_monitor.h"
#include "mpudp_utils.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define FILENAME "libre36.pdf"

void recv_file(monitor_t *m)
{
    uint8_t *data;
    FILE *f = fopen(FILENAME, "w");

    int i = 0, len;
    while(1)
    {
        i++;
        len = mpudp_recv_packet(m, &data);

        if(len > 0)
            fwrite(data, 1, len, f);

        free(data);

        if(len > 0 && len < 1024)
            break;
        /* printf("Got packet %d with %d bytes\n", i, len); */
    }

    printf("End of transmission");
    fclose(f);
    printf("File closed");
}

int main()
{
    monitor_t m;
    init_monitor(&m);

    pthread_create(&m.id, NULL, monitor_thread, &m);

    recv_file(&m);

    pthread_join(m.id, NULL);

    return 0;
}
