#include "mpudp_utils.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

void init_buffer(mpudp_buff_t *buff)
{
    buff->head = 0;
    buff->tail = 0;
    buff->num  = 0;

    pthread_cond_init(&buff->empty, NULL);
    pthread_cond_init(&buff->full,  NULL);
    pthread_mutex_init(&buff->mx,   NULL);
}

int mpudp_prepare_packet(mpudp_packet_t **packet, uint8_t *data, int len)
{
    // TODO: watch the MTU cap
    *packet = malloc(sizeof(mpudp_packet_t));
    mpudp_packet_t *p = *packet;

    p->id = -1;
    p->payload = malloc(len);
    memcpy(p->payload, data, len);
    return len;
}
