#ifndef T_PCAP_UTILS_H
#define T_PCAP_UTILS_H

#include <pcap.h>

#define SYSFS_DEV_PATH "/sys/class/net/"

int pcapu_find_any(pcap_if_t **);
int pcapu_find_dev_by_name(pcap_if_t **, char*);
char* pcapu_read_if_mac_s(char *, char **);
char* pcapu_read_if_ip_s(pcap_if_t*, char **);
void check_root();
void pcapu_print_all_devs();

#endif
