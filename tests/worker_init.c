#include <pthread.h>
#include "mpudp_monitor.h"

int main()
{
    monitor_t m;
    init_monitor(&m);

    pthread_create(&m.id, NULL, monitor_thread, &m);

    pthread_join(m.id, NULL);
    return 0;
}
