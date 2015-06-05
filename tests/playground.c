#include <stdio.h>
#include <stdint.h>
#include "ip_utils.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main()
{
    char ip[] = "192.168.0.1";
    in_addr_t inp;

    inp = inet_addr(ip);
    /* printf("size: %ld\n", sizeof(struct in_addr)); */

    /* printf("reversed: %s\n", inet_ntoa(inp)); */

    uint32_t a = (uint32_t)inp >> 24 & 0xFF;
    uint32_t b = (uint32_t)inp >> 16 & 0xFF;
    uint32_t c = (uint32_t)inp >>  8 & 0xFF;
    uint32_t d = (uint32_t)inp       & 0xFF;

    printf("%d.%d.%d.%d\n", a, b, c, d);

    return 0;
}
