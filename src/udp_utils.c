#include "udp_utils.h"
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int udp_build_dgram_hdr(udp_dgram_t *dgram, uint16_t src, uint16_t dst)
{
    dgram->src_port = src;
    dgram->dst_port = dst;
    dgram->len = 8;
    dgram->crc = 0;
    dgram->data = NULL;

    return 0;
}

int udp_build_dgram(udp_dgram_t *dgram, uint16_t src_port, uint16_t dst_port,
                    char *src_ip, char *dst_ip)
{
    udp_build_dgram_hdr(dgram, src_port, dst_port);

    return 0;
}

int udp_build_pseudo_hdr(udp_pseudo_hdr_t *pseudo, char *src_ip, char *dst_ip)
{
    uint32_t src = inet_addr(src_ip);
    uint32_t dst = inet_addr(dst_ip);

    memcpy(&pseudo->src_ip, &src, 4);
    memcpy(&pseudo->dst_ip, &dst, 4);

    pseudo->padding = 0;

    pseudo->proto = 17;

    uint16_t len = htons(8+12);
    memcpy(&pseudo->len, &len, 2);

    return 0;
}
