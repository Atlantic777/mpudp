#include "mpudp_utils.h"
#include <pthread.h>

void init_buffer(mpudp_buff_t *buff)
{
    buff->head = 0;
    buff->tail = 0;
    buff->num  = 0;

    pthread_cond_init(&buff->empty, NULL);
    pthread_cond_init(&buff->full,  NULL);
    pthread_mutex_init(&buff->mx,   NULL);
}
