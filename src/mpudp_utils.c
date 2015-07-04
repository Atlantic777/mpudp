#include "mpudp_utils.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "mpudp_monitor.h"
#include "net_utils.h"
#include "pcap_utils.h"

void dump_packet(mpudp_packet_t *p)
{
    int i;
    printf("%d:    ", p->id);
    for(i = 0; i < 16; i++)
    {
        printf("%02x ", p->payload[i]);

        if(i == 7)
        {
            printf(" ");
        }
    }
    printf("\n");
}

void init_buffer(mpudp_buff_t *buff)
{
    buff->head = 0;
    buff->tail = 0;
    buff->num  = 0;

    pthread_cond_init(&buff->empty, NULL);
    pthread_cond_init(&buff->full,  NULL);
    pthread_mutex_init(&buff->mx,   NULL);
}

int mpudp_prepare_packet(mpudp_packet_t **packet, uint8_t *data, int len)
{
    // TODO: watch the MTU cap
    *packet = malloc(sizeof(mpudp_packet_t));
    mpudp_packet_t *p = *packet;

    p->id = -1;
    p->payload = malloc(len);
    memcpy(p->payload, data, len);
    p->len = len;
    return len;
}

void mpudp_build_config(int n, char **iface_names_list, mpudp_config_t *config)
{
    config->num_if = n;
    config->if_list = malloc(sizeof(mpudp_if_desc_t)*config->num_if);
    char *tmp;
    pcap_if_t *dev;

    int i;
    for(i = 0; i < config->num_if; i++)
    {
        /* strcpy(config->if_list[i].name, m->workers[i]->name); */
        /* mac2chars(m->workers[i]->src_mac, config->if_list[i].mac); */
        /* ip2chars(m->workers[i]->src_ip, &config->if_list[i].ip); */
        pcapu_find_dev_by_name(&dev, iface_names_list[i]);

        strcpy(config->if_list[i].name, iface_names_list[i]);

        tmp = pcapu_read_if_mac_s(iface_names_list[i], NULL);

        if(tmp == NULL)
            continue;

        mac2chars(tmp, config->if_list[i].mac);

        tmp = pcapu_read_if_ip_s(dev, NULL);
        ip2chars(tmp, &config->if_list[i].ip);

        config->if_list[i].port = 8880+i;
    }
}

int mpudp_config2chars(mpudp_config_t *config, uint8_t **payload)
{
    int PREFIX_LEN = MPUDP_CONFIG_PREFIX_LEN;
    int DESC_LEN = MPUDP_IFACE_DESC_LEN;
    int len = PREFIX_LEN + config->num_if*DESC_LEN;

    *payload = malloc(len);
    char *dest = *payload;

    dest[0] = config->id;
    dest[1] = config->num_if;

    int i;
    for(i = 0; i < config->num_if; i++)
    {
        memcpy(dest+PREFIX_LEN+i*DESC_LEN, &config->if_list[i], DESC_LEN);
    }

    return len;
}

int mpudp_chars2config(mpudp_config_t *config, uint8_t *data, int len)
{
    int DESC_LEN   = MPUDP_IFACE_DESC_LEN;
    int PREFIX_LEN = MPUDP_CONFIG_PREFIX_LEN;

    config->id      = data[0];
    config->num_if  = data[1];
    config->if_list = malloc(DESC_LEN*config->num_if);

    if(config->num_if < 0 || config->num_if > 4)
        return -1;

    int i;
    for(i = 0; i < config->num_if; i++)
    {
        memcpy(&config->if_list[i], data+PREFIX_LEN+DESC_LEN*i, DESC_LEN);
    }

    return 0;
}

int mpudp_packet2chars(mpudp_packet_t *packet, uint8_t **payload)
{
    *payload = malloc(4+4+4+packet->len);
    uint8_t *dst = *payload;

    memcpy(dst, packet, 12);

    if(packet->len > 0 || packet->type < 0 || packet->type > 2)
        memcpy(dst+12, packet->payload, packet->len);

    return 12+packet->len;
}

int mpudp_chars2packet(mpudp_packet_t *packet, uint8_t *payload, int len)
{
    memcpy(packet, payload, 12);

    if(packet->len < 0 || packet->type < 0 || packet->type > 2)
    {
        // silly malloc bug
        return -1;
    }

    packet->payload = malloc(packet->len);
    memcpy(packet->payload, payload+12, packet->len);

    return 0;
}

void mpudp_send_packet(monitor_t *m, uint8_t *data, int len)
{
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));
    p->payload = malloc(len);
    memcpy(p->payload, data, len);
    p->len = len;

    pthread_mutex_lock(&m->tx_mx);


    while(m->tx_num >= BUFF_LEN)
        pthread_cond_wait(&m->tx_not_full, &m->tx_mx);


    p->id = m->pkt_counter++;
    p->type = MPUDP_DATA;

    m->tx_data[m->tx_head] = p;
    m->tx_num++;
    m->tx_head = (m->tx_head+1) % BUFF_LEN;

    /* int i; */
    /* for(i = 0; i < 32; i++) */
    /* { */
    /*     printf("%02x ", m->tx_data[m->tx_tail]->payload[i]); */
    /* } */
    /* printf("\n"); */

    pthread_cond_broadcast(&m->tx_has_data);
    pthread_mutex_unlock(&m->tx_mx);
}

int next_packet_available(monitor_t *m)
{
    int id = -1, i;
    for(i = 0; i < BUFF_LEN; i++)
    {
        if(m->rx_data[i] != NULL)
        {
            if(m->rx_data[i]->id == m->user_expected_id)
            {
                id = i;
            }
        }
    }

    return id;
}

int mpudp_recv_packet(monitor_t *m, uint8_t **data)
{
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));
    int id;

    pthread_mutex_lock(&m->rx_mx);
    while((id = next_packet_available(m)) == -1)
        pthread_cond_wait(&m->rx_has_data, &m->rx_mx);

    p = m->rx_data[id % BUFF_LEN];
    m->rx_data[id % BUFF_LEN] = NULL;

    m->rx_num--;
    m->user_expected_id++;

    /* printf("packet len: %d\n", p->len); */

    /* *data = malloc(sizeof(p->len)); */
    /* memcpy(*data, p->payload, p->len); */
    *data = p->payload;

    pthread_cond_broadcast(&m->rx_not_full);
    pthread_mutex_unlock(&m->rx_mx);

    return p->len;
}

void mpudp_print_config(mpudp_config_t *c)
{
    int i;
    for(i = 0; i < c->num_if; i++)
    {
        mpudp_print_iface_desc(&c->if_list[i]);
        printf("\n");
    }
}

void mpudp_print_iface_desc(mpudp_if_desc_t *if_desc)
{
    char mac[MAC_LEN_S];
    char ip[15];

    puts(if_desc->name);
    puts(chars2mac(if_desc->mac, mac));
    puts(chars2ip(if_desc->ip, ip));
    printf("Port: %d\n", if_desc->port);
}

int mpudp_config_different(mpudp_config_t *c1, mpudp_config_t *c2)
{
    if(c1->num_if != c2->num_if)
    {
        return 1;
    }

    int a, b, match = 0;

    for(a = 0; a < c1->num_if; a++)
    {
        for(b = 0; b < c2->num_if; b++)
        {
            if(c1->if_list[a].ip == c2->if_list[b].ip)
            {
                match++;
            }
        }
    }

    if(match == c1->num_if)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
