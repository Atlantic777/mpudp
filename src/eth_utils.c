#include "eth_utils.h"
#include <stdlib.h>
#include <string.h>

int eth_compile_frame(eth_frame_t *frame,
                      unsigned char *dst_mac,
                      unsigned char *src_mac,
                      unsigned char *eth_type)
{
    if(frame == NULL)
    {
        return -1;
    }

    mac2chars(src_mac, frame->src);
    mac2chars(dst_mac, frame->dst);

    memcpy(frame->type, eth_type, 2);

    return 0;
}
