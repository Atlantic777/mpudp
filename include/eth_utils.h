#ifndef ETH_UTILS_H
#define ETH_UTILS_H

#include "net_utils.h"
#define ETH_FRAME_PREFIX_LEN (2*MAC_LEN+2) // 14
#define ETH_TYPE_IP "\x08\x00"

typedef struct eth_frame {
    unsigned char src[MAC_LEN];
    unsigned char dst[MAC_LEN];
    unsigned char type[2];
    unsigned char *data;
    int data_len;
} eth_frame_t;

int eth_build_frame(eth_frame_t*,
        char*,
        char*,
        unsigned char*);

int eth_set_data(eth_frame_t*, unsigned char*, int);
int eth_frame_len(eth_frame_t*);
int eth_frame2chars(eth_frame_t *, unsigned char**);
int eth_read_frame(eth_frame_t*, unsigned char*, int);

#endif
