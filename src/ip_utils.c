#include "ip_utils.h"
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>

int ip_build_packet(ip_packet_t *packet, char *src_ip, char *dst_ip)
{
    ip_hdr_set_common(packet);

    ip_hdr_set_addr(packet, ADDR_SRC, src_ip);
    ip_hdr_set_addr(packet, ADDR_DST, dst_ip);

    return 0;
}

void ip_hdr_set_common(ip_packet_t *packet)
{
    // set ip proto version to IPv4
    // and set internet header len to 20
    set_octet(&packet->first, 3, 4 << 4 | 5);

    // set initial total length just to header len (in bytes)
    ip_set_len(packet, 20);

    // set type of service to zero - we don't use it
    set_octet(&packet->first, 2, 0);

    // set id, fragment num and fragmentation bits to 0
    packet->second = 0;

    // set TTL to 16
    set_octet(&packet->third, 3, 16);

    // set protocol to UDP
    set_octet(&packet->third, 2, PROTO_UDP);
}

void set_octet(uint32_t *quad, uint8_t pos, uint8_t val)
{
    // reset the byte
    *quad = *quad & ~(0xFF << pos*8);

    // set the byte
    *quad = *quad | (val << pos*8);
}

void set_double(uint32_t *quad, uint8_t pos, uint16_t val)
{
    // reset the two-byte
    *quad = *quad & ~(0xFFFF << pos*16);

    // set the two-byte
    *quad = *quad | (val << pos*16);

}

uint8_t get_octet(uint32_t *quad, uint8_t pos)
{
    // casting will do the masking
    return (uint8_t)(*quad >> pos*8);
}

uint16_t get_double(uint32_t *quad, uint8_t pos)
{
    // casting will do the masking
    return (uint16_t)(*quad >> pos*16);
}

void ip_print_packet(ip_packet_t *packet)
{
    puts("\nDUMPING IP PACKET");
    printf("Version:\t%d\n", ip_get_version(packet));
    printf("IHL:\t\t%u\n", ip_get_ihl(packet));
    printf("Len:\t\t%u\n", ip_get_len(packet));
    printf("TOS:\t\t%u\n", ip_get_tos(packet));
    printf("TTL:\t\t%u\n", ip_get_ttl(packet));
    printf("Proto:\t\t%u\n", ip_get_proto(packet));
    printf("Src:\t\t%s\n", ip_hdr_get_addr_s(packet, ADDR_SRC));
    printf("Dst:\t\t%s\n", ip_hdr_get_addr_s(packet, ADDR_DST));
}

uint8_t ip_get_version(ip_packet_t *packet)
{
    return get_octet(&packet->first, 3) >> 4;
}

uint8_t ip_get_ihl(ip_packet_t *packet)
{
    return get_octet(&packet->first, 3) & 0xF;
}

uint8_t ip_get_tos(ip_packet_t *packet)
{
    return get_octet(&packet->first, 2);
}

uint8_t ip_get_ttl(ip_packet_t *packet)
{
    return get_octet(&packet->third, 3);
}

uint8_t ip_get_proto(ip_packet_t *packet)
{
    return get_octet(&packet->third, 2);
}

uint16_t ip_get_crc(ip_packet_t *packet)
{
    // return crc
    // return get_octet(&packet->third)
    return -1;
}

int ip_hdr_set_addr(ip_packet_t *packet, int way, char *addr)
{
    in_addr_t a = inet_addr(addr);
    uint32_t  b = ntohl(a);
    memcpy(packet+way*4, &b, 4);
    return 0;
}

uint32_t ip_hdr_get_addr(ip_packet_t *packet, int way)
{
    uint32_t res;
    memcpy(&res, packet+way*4, 4);
    return res;
}

char* ip_hdr_get_addr_s(ip_packet_t *packet, int way)
{
    struct in_addr addr;
    uint32_t my_addr = ip_hdr_get_addr(packet, way);
    uint32_t rev = htonl(my_addr);
    memcpy(&addr, &rev, 4);

    return inet_ntoa(addr);
}

uint16_t ip_get_len(ip_packet_t *packet)
{
    return get_double(&packet->first, 0);
}

uint16_t ip_set_len(ip_packet_t *packet, uint16_t len)
{
    set_double(&packet->first, 0, len);
    return 0;
}

int ip_hdr2chars(ip_packet_t *packet, unsigned char *buff)
{
    int i;

    *(buff+0) = ip_get_version(packet)<<4 | ip_get_ihl(packet);
    *(buff+1) = ip_get_tos(packet);

    *(buff+2) = ip_get_len(packet) >> 8;
    *(buff+3) = ip_get_len(packet)  & 0xFF;

    for(i = 4; i < 8; i++)
        *(buff+i) = 0;

    *(buff+8) = ip_get_ttl(packet);
    *(buff+9) = ip_get_proto(packet);
    *(buff+10) = ip_get_crc(packet) >> 8;
    *(buff+11) = ip_get_crc(packet)  & 0xFF;

    for(i = 0; i < 4; i++)
        *(buff+12+i) = ip_hdr_get_addr(packet, ADDR_SRC) >> ( ( 3-i )*8 );

    for(i = 0; i < 4; i++)
        *(buff+16+i) = ip_hdr_get_addr(packet, ADDR_DST) >> ( ( 3-i )*8 );
}

int ip_packet2chars(ip_packet_t *packet, unsigned char **buff)
{
    uint16_t len = ip_get_len(packet);
    *buff = malloc(len);

    ip_hdr2chars(packet, *buff);
}
