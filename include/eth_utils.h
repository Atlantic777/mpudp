#ifndef ETH_UTILS_H
#define ETH_UTILS_H

#include "net_utils.h"

typedef struct eth_frame {
    char src[MAC_LEN];
    char dst[MAC_LEN];
    char type[2];
} eth_frame_t;

int eth_compile_frame(eth_frame_t*, char*, char*, char*);

#endif
