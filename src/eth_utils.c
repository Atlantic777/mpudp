#include "eth_utils.h"
#include <stdlib.h>

int eth_compile_frame(eth_frame_t *frame,
                      char *src_mac,
                      char *dst_mac,
                      char *eth_type)
{
    if(frame == NULL)
    {
        return -1;
    }

    return 0;
}
