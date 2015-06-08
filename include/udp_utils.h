#ifndef UDP_UTILS_H
#define UDP_UTILS_H

#include <stdint.h>

typedef struct udp_dgram udp_dgram_t;
typedef struct udp_pseudo_hdr udp_pseudo_hdr_t;

struct udp_dgram {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t crc;
    udp_pseudo_hdr_t *pseudo;
    uint8_t *data;
};

struct udp_pseudo_hdr {
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint8_t  padding;
    uint8_t  proto;
    uint8_t len[2];
    uint16_t src_port;
    uint16_t dst_port;
};


int udp_build_dgram_hdr(udp_dgram_t *, uint16_t, uint16_t);
int udp_build_dgram(udp_dgram_t *, uint16_t, uint16_t, char*, char*);
int udp_build_pseudo_hdr(udp_pseudo_hdr_t *, char*, char*);
int udp_dgram2chars(udp_dgram_t*, unsigned char**);
int udp_set_data(udp_dgram_t*, uint8_t*, int);
int udp_read_dgram(udp_dgram_t*, uint8_t*, int);

#endif
