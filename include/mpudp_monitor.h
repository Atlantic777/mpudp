#ifndef MONITOR_H
#define MONITOR_H

#include "mpudp_utils.h"

typedef struct monitor monitor_t;

struct monitor {
    pthread_t    id;
    mpudp_buff_t buff;
};

void* monitor_thread(void*);
void init_monitor(monitor_t *);

#endif
