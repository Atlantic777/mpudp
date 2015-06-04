#include <pcap.h>
#include "pcap_utils.h"
#include <stdio.h>
#include <string.h>
#include <net_utils.h>
#include <stdlib.h>
#include <unistd.h>

int pcapu_find_any(pcap_if_t **dev)
{
    if(dev == NULL)
    {
        return -1;
    }

    pcap_if_t *alldevs, *d;
    char eb[PCAP_ERRBUF_SIZE];

    pcap_findalldevs(&alldevs, eb);

    for(d = alldevs; d != NULL; d = d->next)
    {
        if(strstr(d->name, "eth") || strstr(d->name, "wlan"))
        {
            *dev = d;
            return 0;
        }
    }

    return -1;
}

int pcapu_find_dev_by_name(pcap_if_t **dev, char *name)
{
    if(dev == NULL || name == NULL || strlen(name) == 0)
    {
        return -1;
    }

    pcap_if_t *alldevs, *d;
    char eb[PCAP_ERRBUF_SIZE];

    pcap_findalldevs(&alldevs, eb);

    for(d = alldevs; d != NULL; d = d->next)
    {
        if(strstr(d->name, name))
        {
            *dev = d;
            return 0;
        }
    }
}

char* pcapu_read_if_mac_s(char *dev_name, char **mac_s)
{
    char path[256];
    char *addr = NULL;
    size_t n = MAC_LEN_S;

    sprintf(path, "%s%s/address", SYSFS_DEV_PATH, dev_name);
    FILE *f = fopen(path, "r");

    getline(&addr, &n, f);
    fclose(f);

    if(mac_s != NULL)
    {
        *mac_s = addr;
    }

    return addr;
}

void check_root()
{
    if(getuid() != 0)
    {
        puts("You should run this as root!");
        exit(-1);
    }
}
