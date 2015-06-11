#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stdint.h>

#define MAC_LEN_S 18 // MAC address string buffer length
#define MAC_LEN   6  // MAC address length in bytes
#define BCAST_MAC_S "FF:FF:FF:FF:FF:FF"
#define BCAST_MAC_B "\xFF\xFF\xFF\xFF\xFF\xFF"


int mac2chars(char*, unsigned char*);
char* chars2mac(unsigned char*, char*);
uint32_t ip2chars(char*, uint32_t*);

#endif
