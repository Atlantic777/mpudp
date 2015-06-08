#include <stdio.h>
#include "mpudp_worker.h"
#include "pcap_utils.h"

int main()
{
    char *if_name = "wlan2";

    worker_t w;
    pcapu_find_dev_by_name(&w.if_desc, if_name);

    puts(w.if_desc->name);
    puts(pcapu_read_if_mac_s(w.if_desc->name, NULL));
    puts(pcapu_read_if_ip_s(w.if_desc, NULL));

    return 0;
}
