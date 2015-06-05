#ifndef IP_UTILS_H
#define IP_UTILS_H

#include <sys/types.h>
#include <stdint.h>

struct ip_packet {
    uint32_t first;
    uint32_t second;
    uint32_t third;
    uint32_t fourth;
};

typedef struct ip_packet ip_packet_t;

int ip_build_packet(ip_packet_t *, char*, char*);
void ip_hdr_set_common(ip_packet_t *);
void set_octet(uint32_t *, uint8_t pos, uint8_t val);

#endif
