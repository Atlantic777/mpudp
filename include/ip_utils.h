#ifndef IP_UTILS_H
#define IP_UTILS_H

#include <sys/types.h>
#include <stdint.h>

#define PROTO_UDP 0x11
#define ADDR_SRC  3
#define ADDR_DST  4

struct ip_packet {
    uint32_t first;
    uint32_t second;
    uint32_t third;
    uint32_t fourth;
};

typedef struct ip_packet ip_packet_t;

int ip_hdr_set_addr(ip_packet_t *, int, char*);
uint32_t ip_hdr_get_addr(ip_packet_t *, int);
uint8_t ip_get_version(ip_packet_t *);
uint8_t ip_get_ihl(ip_packet_t *);
uint8_t ip_get_tos(ip_packet_t *);
uint8_t ip_get_ttl(ip_packet_t *);
uint8_t ip_get_proto(ip_packet_t *);
uint16_t ip_get_crc(ip_packet_t *);
uint16_t ip_get_len(ip_packet_t *);
uint16_t ip_set_len(ip_packet_t *, uint16_t);

char* ip_hdr_get_addr_s(ip_packet_t*, int);

int ip_build_packet(ip_packet_t *, char*, char*);
void ip_hdr_set_common(ip_packet_t *);

void set_octet(uint32_t *, uint8_t, uint8_t);
uint8_t get_octet(uint32_t *, uint8_t);
void set_double(uint32_t *, uint8_t, uint16_t);
uint16_t get_double(uint32_t *, uint8_t);

void ip_print_packet(ip_packet_t *);

int ip_packet2chars(ip_packet_t *, unsigned char **);

#endif
