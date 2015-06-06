#ifndef UDP_UTILS_H
#define UDP_UTILS_H

#include <stdint.h>

struct udp_dgram {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t crc;
};

typedef struct udp_dgram udp_dgram_t;

int udp_build_dgram_hdr(udp_dgram_t *, uint16_t, uint16_t);

#endif
