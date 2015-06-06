#include "udp_utils.h"
#include <string.h>

int udp_build_dgram_hdr(udp_dgram_t *dgram, uint16_t src, uint16_t dst)
{
    uint16_t r_src = ntohl(src);
    uint16_t r_dst = ntohl(dst);

    memcpy(&dgram->src_port, &r_src, 2);
    memcpy(&dgram->dst_port, &r_dst, 2);

    dgram->len = 8;
    dgram->crc = 0;

    return 0;
}
