#include <stdio.h>
#include "mpudp_monitor.h"
#include "mpudp_utils.h"
#include <stdlib.h>

/* #define FILENAME "libre36.pdf" */
/* #define FILENAME "linux-4.1.tar.xz" */
#define FILENAME "raspbian.zip"

#define PKT_LEN 1024

void send_file(monitor_t *m)
{
    uint8_t data[PKT_LEN];
    int n_read, cnt = 0;

    FILE *f = fopen(FILENAME, "r");

    int i;

    while(n_read = fread(data, 1, PKT_LEN, f))
    {
        mpudp_send_packet(m, data, n_read);
        /* printf("User sent %d bytes, cnt: %d\n", n_read, cnt); */
        cnt++;
    }

    puts("End of transmission!");

    fclose(f);
}

int main()
{
    monitor_t m;
    init_monitor(&m);

    pthread_create(&m.id, NULL, monitor_thread, &m);

    send_file(&m);

    pthread_join(m.id, NULL);

    return 0;
}
