#ifndef NET_UTILS_H
#define NET_UTILS_H

#define MAC_LEN_S 18 // MAC address string buffer length
#define MAC_LEN   6  // MAC address length in bytes

int mac2chars(unsigned char*, unsigned char*);
int chars2mac(unsigned char*, char*);

#endif
