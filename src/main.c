#include <pcap.h>
#include <stdio.h>

int main()
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    pcap_findalldevs(&alldevs, errbuf);

    pcap_if_t *current = alldevs;

    while(current) {
        printf("%s - %s\n", current->name, current->description);
        current = current->next;
    }

    return 0;
}
