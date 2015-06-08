#include "udp_utils.h"
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

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

    udp_pseudo_hdr_t pseudo;
    udp_build_pseudo_hdr(&pseudo, src_ip, dst_ip);

    udp_assign_pseudo_hdr(dgram, &pseudo);

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

int udp_assign_pseudo_hdr(udp_dgram_t *dgram, udp_pseudo_hdr_t *pseudo)
{
    dgram->pseudo = pseudo;

    memcpy(&dgram->len, pseudo->len, 2);
    dgram->len = ntohs(dgram->len);

    return 0;
}

int udp_pseudo2chars(udp_pseudo_hdr_t *pseudo, unsigned char *buff)
{
    memcpy(buff+8 , pseudo->src_ip, 4);
    memcpy(buff+12, pseudo->dst_ip, 4);
    memcpy(buff+16, &pseudo->padding, 1);
    memcpy(buff+17, &pseudo->proto, 1);
    memcpy(buff+18, pseudo->len, 2);

    return 0;
}

int udp_dgram2chars(udp_dgram_t *dgram, unsigned char **buff)
{
    *buff = malloc(dgram->len);

    uint16_t r_src = htons(dgram->src_port);
    uint16_t r_dst = htons(dgram->dst_port);
    uint16_t r_len = htons(dgram->len);
    uint16_t r_crc = htons(dgram->crc);

    memcpy(*buff+0, &r_src, 2);
    memcpy(*buff+2, &r_dst, 2);
    memcpy(*buff+4, &r_len, 2);
    memcpy(*buff+6, &r_crc, 2);

    memcpy(*buff+8, dgram->data, dgram->len-8);

    return dgram->len;
}

int udp_set_data(udp_dgram_t *dgram, uint8_t *data, int len)
{

    dgram->len = len+8;
    dgram->data = malloc(len);

    memcpy(dgram->data, data, len);

    return 0;
}

int udp_read_dgram(udp_dgram_t *dgram, uint8_t *data, int len)
{
    dgram->src_port = data[0] << 8 | data[1];
    dgram->dst_port = data[2] << 8 | data[3];
    dgram->len      = data[4] << 8 | data[5];
    dgram->crc      = data[6] << 8 | data[7];

    dgram->data = malloc(dgram->len-8);
    memcpy(dgram->data, data+8, dgram->len-8);

    return 0;
}
