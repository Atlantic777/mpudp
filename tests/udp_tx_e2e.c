#include <stdio.h>
#include <string.h>
#include "net_utils.h"
#include "eth_utils.h"
#include "ip_utils.h"
#include "udp_utils.h"
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>

int main()
{

    char msg[] = "Hello world!\n";

    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t dgram;

    uint16_t src_port = 6666;
    uint16_t dst_port = 8888;
    char src_ip[] = "192.168.101.1";
    char dst_ip[] = "192.168.101.2";
    char src_mac[] = "74:e5:0b:85:88:8a";
    char dst_mac[] = "00:0f:13:97:11:fa";
    unsigned char type[] = ETH_TYPE_IP;

    unsigned char *udp_payload;
    unsigned char *ip_payload;
    unsigned char *eth_payload;

    int udp_len, ip_len, eth_len;

    eth_compile_frame(&eth_frame, dst_mac, src_mac, ETH_TYPE_IP);
    ip_build_packet(&ip_packet, src_ip, dst_ip);
    udp_build_dgram_hdr(&dgram, src_port, dst_port);

    udp_set_data(&dgram, msg, strlen(msg));
    udp_len = udp_dgram2chars(&dgram, &udp_payload);

    ip_set_data(&ip_packet, udp_payload, udp_len);
    ip_len = ip_packet2chars(&ip_packet, &ip_payload);

    eth_set_data(&eth_frame, ip_payload, ip_len);
    eth_len = eth_frame2chars(&eth_frame, &eth_payload);


    printf("UDP len: %d\n", udp_len);
    printf("IP len:  %d\n", ip_len);
    printf("Eth len: %d\n", eth_len);

    // sending everything
    pcap_if_t *dev = malloc(sizeof(pcap_if_t));
    pcapu_find_dev_by_name(&dev, "wlan2");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_live(dev->name, 1024, 1, 1000, errbuf);

    pcap_sendpacket(h, eth_payload, eth_len);

    pcap_close(h);

    return 0;
}
