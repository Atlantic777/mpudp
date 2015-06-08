#include "eth_utils.h"
#include <stdlib.h>
#include <string.h>

int eth_build_frame(eth_frame_t *frame,
                      char *dst_mac,
                      char *src_mac,
                      unsigned char *eth_type)
{
    if(frame == NULL)
    {
        return -1;
    }

    mac2chars(src_mac, frame->src);
    mac2chars(dst_mac, frame->dst);

    memcpy(frame->type, eth_type, 2);
    frame->data = NULL;
    frame->data_len = 0;

    return 0;
}

int eth_set_data(eth_frame_t *frame, unsigned char *payload, int len)
{
    if(frame->data != NULL)
    {
        free(frame->data);
    }

    frame->data = calloc(sizeof(unsigned char), len);
    memcpy(frame->data, payload, len);

    frame->data_len = len;

}

int eth_frame_len(eth_frame_t *frame)
{
    return ETH_FRAME_PREFIX_LEN+frame->data_len;
}

int eth_frame2chars(eth_frame_t *frame, unsigned char **buff)
{
    *buff = malloc(eth_frame_len(frame));

    memcpy(*buff, frame->dst, MAC_LEN);
    memcpy(*buff+MAC_LEN, frame->src, MAC_LEN);
    memcpy(*buff+2*MAC_LEN, frame->type, 2);
    memcpy(*buff+ETH_FRAME_PREFIX_LEN, frame->data, frame->data_len);

    return eth_frame_len(frame);
}

int eth_read_frame(eth_frame_t *frame, unsigned char *data, int len)
{
    memcpy(frame->dst, data, MAC_LEN);
    memcpy(frame->src, data+MAC_LEN, MAC_LEN);
    memcpy(frame->type, data+2*MAC_LEN, 2);

    frame->data_len = len-ETH_FRAME_PREFIX_LEN;
    frame->data = malloc(frame->data_len);;
    memcpy(frame->data, data+ETH_FRAME_PREFIX_LEN, frame->data_len);

    return 0;
}
