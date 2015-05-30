#include "net_utils.h"
#include <stdio.h>

int mac2chars(unsigned char *mac_string, unsigned char *dest)
{
    int i;
    int cursor = 0;
    unsigned char byte_buff[5] = "0x";

    for(i = 0; i < MAC_LEN_S; i++)
    {
        if(isxdigit(mac_string[i]))
        {
            byte_buff[2+cursor++] = mac_string[i];
        }
        else if(mac_string[i] == ':' || mac_string[i] == 0)
        {
            byte_buff[2+cursor] = 0;
            sscanf(byte_buff, "%hhx", &dest[i/3]);
            cursor = 0;
        }
    }

    return 0;
}
