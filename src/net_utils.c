#include "net_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

int mac2chars(char *mac_string, unsigned char *dest)
{
    int i;
    int cursor = 0;
    unsigned char byte_buff[5] = "0x";

    // Has to be MAC_LEN_S because strlen() doesn't count terminator
    if(strlen(mac_string) != MAC_LEN_S-1)
    {
        return -1;
    }

    for(i = 0; i < MAC_LEN_S; i++)
    {
        if(isxdigit(mac_string[i]) && cursor < 2)
        {
            byte_buff[2+cursor++] = mac_string[i];
        }
        else if(mac_string[i] == ':' || mac_string[i] == 0 && cursor == 2)
        {
            byte_buff[2+cursor] = 0;
            sscanf(byte_buff, "%hhx", &dest[i/3]);
            cursor = 0;
        }
        else
        {
            return -1;
        }
    }

    return 0;
}

char* chars2mac(unsigned char *mac_raw, char *mac_string)
{
    int i;
    for(i = 0; i < MAC_LEN-1; i++)
    {
        sprintf(mac_string+i*3, "%02x:", mac_raw[i]);
    }

    sprintf(mac_string+i*3, "%02x", mac_raw[i]);

    return mac_string;
}

uint32_t ip2chars(char *ip_string, uint32_t *dst)
{
    uint32_t b_ip;

    inet_pton(AF_INET, ip_string, &b_ip);
    b_ip = htonl(b_ip);

    if(dst != NULL)
    {
        *dst = b_ip;
    }

    return b_ip;
}

char* chars2ip(uint32_t src, char *dst)
{
    uint32_t b_ip = ntohl(src);
    inet_ntop(AF_INET, &b_ip, dst, IP_LEN_S_MAX);
    return dst;
}
