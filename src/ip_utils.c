#include "ip_utils.h"

int ip_build_packet(ip_packet_t *packet, char *src_ip, char *dst_ip)
{
    return -1;

}

void ip_hdr_set_common(ip_packet_t *packet)
{

}

void set_octet(uint32_t *quad, uint8_t pos, uint8_t val)
{
    // reset the byte
    *quad = *quad & ~(0xFF << pos*8);

    // set the byte
    *quad = *quad | (val << pos*8);
}
