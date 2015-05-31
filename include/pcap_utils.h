#ifndef T_PCAP_UTILS_H
#define T_PCAP_UTILS_H

#include <pcap.h>

#define SYSFS_DEV_PATH "/sys/class/net/"

int pcapu_find_any(pcap_if_t **);
char* pcapu_read_if_mac_s(char *, char **);

#endif
