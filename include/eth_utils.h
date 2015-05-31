#ifndef ETH_UTILS_H
#define ETH_UTILS_H

#include "net_utils.h"

typedef struct eth_frame {
    unsigned char src[MAC_LEN];
    unsigned char dst[MAC_LEN];
    unsigned char type[2];
    unsigned char *data;
    int data_len;
} eth_frame_t;

int eth_compile_frame(eth_frame_t*,
        char*,
        char*,
        unsigned char*);

#endif
