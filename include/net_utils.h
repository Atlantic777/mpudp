#ifndef NET_UTILS_H
#define NET_UTILS_H

#define MAC_LEN_S 18 // MAC address string buffer length
#define MAC_LEN   6  // MAC address length in bytes
#define BCAST_MAC_S "FF:FF:FF:FF:FF:FF"

int mac2chars(char*, unsigned char*);
char* chars2mac(unsigned char*, char*);

#endif
