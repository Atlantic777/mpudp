#include <pcap.h>
#include <stdio.h>
#include "eth_utils.h"
#include "net_utils.h"
#include <stdlib.h>
#include <time.h>

int main()
{
    char errbuf[256];

    /* pcap_t *dev = pcap_open_live("eth0", 1024, 1, 1000, errbuf); */
    pcap_t *dev = pcap_open_dead(DLT_EN10MB, 1024);
    if(dev == NULL) puts(errbuf);

    pcap_dumper_t *dump = pcap_dump_open(dev, "dump.pcap");
    if(dump == NULL) puts(errbuf);

    eth_frame_t frame;
    eth_compile_frame(&frame, "00:1f:d0:b5:bf:83", "f0:de:f1:dc:2c:60", "\x80\x00");

    unsigned char *buff;
    int len = eth_frame_len(&frame);
    buff = malloc(len);

    printf("len: %d\n", len);

    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec = time(NULL);
    hdr.ts.tv_usec = 0;
    hdr.caplen = 14;
    hdr.len = 14;

    eth_frame2chars(&frame, &buff);
    /* pcap_sendpacket(dev, buff, len); */
    pcap_dump((unsigned char*)dump, &hdr, buff);
    pcap_dump_flush(dump);

    pcap_t *read = pcap_open_offline("dump.pcap", errbuf);

    if(read == NULL)
    {
        puts("failed to open file for reading");
        return -1;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    puts("here");
    pcap_next_ex(read, &header, &data);
    puts("there");

    int i;
    for(i = 0; i < header->len; i++)
    {
        printf("%02x\n", data[i]);
    }
    puts("end of data");
    return 0;
}
