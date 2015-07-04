#include "mpudp_worker.h"
#include <stdio.h>
#include <stdlib.h>
#include "eth_utils.h"
#include "ip_utils.h"
#include "udp_utils.h"
#include "pcap_utils.h"
#include <pcap.h>
#include <string.h>
#include <time.h>

void timestamp()
{
    struct timeval tv;
    struct tm *t;

    gettimeofday(&tv, NULL);
    t = localtime(&tv.tv_sec);

    printf("[%02d:%03d] ", t->tm_sec, (int)tv.tv_usec/1000);
}

void* worker_tx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;

    while(1)
    {
        pthread_mutex_lock(&w->private_tx_buff_mx);
        while(w->private_tx_buff == NULL)
        {
            pthread_cond_wait(&w->tx_ready, &w->private_tx_buff_mx);
        }

        /* timestamp(); */
        /* printf("[%d] - tx thread wakeup\n", w->id); */

        /* dump_packet(w->private_tx_buff); */

        if(w->private_tx_buff->type == MPUDP_CONFIG)
        {
            worker_send(w, w->private_tx_buff, SEND_BCAST);
        }
        else if(w->private_tx_buff->type == MPUDP_DATA)
        {
            worker_send(w, w->private_tx_buff, SEND_UCAST);

            /* dump_packet(w->private_tx_buff); */
        }
        else
        {
            // we are sending ACK
            worker_send(w, w->private_tx_buff, SEND_UCAST);
        }

        /* usleep(w->choke); */
        /* sleep(1); */

        w->private_tx_buff = NULL;

        pthread_cond_broadcast(&w->tx_empty);
        pthread_cond_broadcast(&m->tx_has_data);

        pthread_mutex_unlock(&w->private_tx_buff_mx);
        /* printf("[%d] - tx thread finished and unlocked private\n", w->id); */
    }
}

void* worker_rx_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;
    mpudp_packet_t *p = malloc(sizeof(mpudp_packet_t));
    mpudp_packet_t *target;
    int res;

    while(1)
    {
        if(worker_recv_packet(w, p))
        {
            if(p->type == MPUDP_CONFIG)
            {
                mpudp_config_t *config = malloc(sizeof(mpudp_config_t));
                res = mpudp_chars2config(config, p->payload, p->len);

                if(res == -1)
                    continue;

                pthread_mutex_lock(&w->m->remote_config_mx);
                if(config->id > w->m->remote_config->id)
                {
                    /* printf("[%d] - We have a new config!\n", w->id); */
                    w->m->remote_config = config;

                    pthread_cond_signal(&w->m->remote_config_changed);
                }
                pthread_mutex_unlock(&w->m->remote_config_mx);

            }
            else if(p->type == MPUDP_DATA)
            {
                /* printf("[%d] - got data packet %d!\n", w->id, p->id); */
                pthread_mutex_lock(&w->m->rx_mx);
                while(w->m->rx_num >= BUFF_LEN)
                    pthread_cond_wait(&w->m->rx_not_full, &w->m->rx_mx);

                if((w->m->rx_data[p->id % BUFF_LEN] == NULL) &&
                        (p->id >= w->m->user_expected_id) &&
                        (p->id < w->m->user_expected_id+BUFF_LEN))
                {
                    /* printf("[%d] - accepting new packet %d\n", w->id, p->id); */
                    target = malloc(sizeof(mpudp_packet_t));
                    w->m->rx_data[p->id % BUFF_LEN] = target;

                    *target = *p;
                    /* printf("target len: %d\n", target->len); */

                    /* target->payload = malloc(sizeof(p->len)); */
                    /* printf("target: %p\n", target->payload); */
                    /* printf("packet: %p\n", p->payload); */
                    target->payload = p->payload;

                    /* memcpy(target->payload, p->payload, p->len); */

                    worker_send_ack(w, p->id);
                    w->m->rx_num++;

                }
                else if(p->id < w->m->user_expected_id)
                {
                    // old packet
                    worker_send_ack(w, p->id);
                    printf("[%d] - confirming old packet %d\n", w->id, p->id);
                }
                else
                {
                    // droping packet
                    printf("[%d] - droping packet: %d\n", w->id, p->id);
                }

                pthread_cond_broadcast(&w->m->rx_has_data);
                pthread_mutex_unlock(&w->m->rx_mx);
            }
            else if(p->type == MPUDP_ACK)
            {
                /* timestamp(); */
                /* printf("[%d] - got ACK %d\n", w->id, p->id); */

                pthread_mutex_lock(&w->wait_ack_buff_mx);
                int i;
                for(i = 0; i < BUFF_LEN; i++)
                {
                    if(w->wait_ack_buff[i] != NULL && (w->wait_ack_buff[i]->id == p->id))
                    {
                        /* timestamp(); */
                        /* printf("[%d] - found matching ACK %d\n", w->id, p->id); */
                        free(w->wait_ack_buff[i]->payload);
                        w->wait_ack_buff[i] = NULL;
                        w->arq_count[i] = 0;

                        if(slide_window(w))
                        {
                            /* printf("[%d] - tx watcher notified\n", w->id); */
                            pthread_cond_broadcast(&w->m->tx_has_data);
                        }
                        break;
                    }
                }
                pthread_mutex_unlock(&w->wait_ack_buff_mx);
            }
        }
    }
}

worker_t* init_worker(int id, char *iface_name, monitor_t *m, float choke)
{
    worker_t *w = malloc(sizeof(worker_t));
    w->m = m;
    w->id = id;
    w->choke = choke*1000000;


    w->private_tx_buff = NULL;

    char *tmp;

    strncpy(w->name, iface_name, 6);

    pcapu_find_dev_by_name(&w->if_desc, iface_name);

    w->src_port = 6666;
    w->dst_port = 8880 + w->id;

    // config src mac
    tmp = pcapu_read_if_mac_s(w->if_desc->name, NULL);
    w->src_mac = malloc(strlen(tmp)+1);
    strcpy(w->src_mac, tmp);

    // config bcast mac
    w->bcast_mac = malloc(MAC_LEN_S);
    strcpy(w->bcast_mac, BCAST_MAC_S);

    // config src ip
    tmp = pcapu_read_if_ip_s(w->if_desc, NULL);
    w->src_ip = malloc(strlen(tmp)+1);
    strcpy(w->src_ip, tmp);

    // config bcast ip
    tmp = pcapu_read_if_bcast_s(w->if_desc, NULL);
    w->bcast_ip = malloc(strlen(tmp)+1);
    strcpy(w->bcast_ip, tmp);

    // alocate space for remote addressess
    w->dst_ip  = malloc(IP_LEN_S_MAX);
    w->dst_mac = malloc(MAC_LEN_S);


    char errbuf[PCAP_ERRBUF_SIZE];

    w->if_handle = pcap_open_live(w->if_desc->name, 2000, 0, 5, errbuf);
    w->state = WORKER_NOT_CONNECTED;

    pthread_mutex_init(&w->config_mx, NULL);
    pthread_mutex_init(&w->private_tx_buff_mx, NULL);


    pthread_cond_init(&w->tx_empty, NULL);
    pthread_cond_init(&w->tx_ready, NULL);

    // new ACK stuff
    pthread_mutex_init(&w->wait_ack_buff_mx, NULL);
    w->ack_num = 0;


    int i;
    for(i = 0; i < BUFF_LEN; i++)
    {
        w->wait_ack_buff[i] = NULL;
        w->arq_count[i] = 0;
        gettimeofday(&w->last_send_time[i], NULL);
    }


    w->ack_head = 0;
    w->ack_tail = 0;

    return w;
}

int spawn_worker(worker_t *w)
{
    pthread_create(&w->tx_thread_id, NULL, &worker_tx_thread, w);
    pthread_create(&w->rx_thread_id, NULL, &worker_rx_thread, w);
    pthread_create(&w->global_tx_watcher_id,NULL,&worker_tx_watcher_thread, w);
    pthread_create(&w->arq_watcher_id, NULL, &worker_arq_watcher, w);
}


void* worker_tx_watcher_thread(void *arg)
{
    worker_t *w = (worker_t*)arg;
    monitor_t *m = w->m;
    mpudp_packet_t *tmp, *esc_tmp;
    int ack_target;

    while(1)
    {
        pthread_mutex_lock(&m->tx_mx);
        while(watchdog_check_state(w))
        {
            pthread_mutex_unlock(&w->private_tx_buff_mx);
            pthread_mutex_unlock(&w->wait_ack_buff_mx);
            pthread_mutex_unlock(&m->esc_mx);
            pthread_cond_wait(&m->tx_has_data, &m->tx_mx);
            /* printf("[%d] - tx watcher woke up\n", w->id); */
        }

        /* timestamp(); */
        /* printf("[%d] - tx watcher can fetch\n", w->id); */
        /* dump_packet(m->tx_data[m->tx_tail]); */

        if(m->checkin[w->id] == 1)
        {
            // just send broadcast
            tmp = m->bcast_data;

            m->checkin[w->id] = 0;
            pthread_cond_broadcast(&m->bcast_done);
            pthread_cond_signal(&w->tx_ready);
            w->private_tx_buff = tmp;
        }
        else
        {
            // we are sending either escape or new data
            if(m->esc_num > 0)
            {
                // get escape packet
                tmp = m->esc_data[m->esc_tail];
                m->esc_tail = (m->esc_tail + 1) % (BUFF_LEN*2);
                m->esc_num--;
                printf("[%d] - gotcha! %d\n", w->id, tmp->id);
            }
            else
            {
                // if we are sending regular data
                tmp = m->tx_data[m->tx_tail];
                m->tx_num--;
                m->tx_tail = (m->tx_tail+1) % BUFF_LEN;
            }
            /* printf("[%d] - updated ACK num to %2d", w->id, w->ack_num); */
            /* printf(" for packet %d\n", tmp->id); */

            ack_target = w->ack_head;

            w->wait_ack_buff[ack_target] = tmp;
            w->ack_head = (w->ack_head + 1) % BUFF_LEN;
            w->ack_num++;
            w->arq_count[ack_target] = 0;
            gettimeofday(&w->last_send_time[ack_target], NULL);

            w->private_tx_buff = tmp;
            pthread_cond_signal(&w->tx_ready);
            pthread_cond_broadcast(&m->tx_not_full);
        }
        pthread_mutex_unlock(&m->tx_mx);
        pthread_mutex_unlock(&w->private_tx_buff_mx);
        pthread_mutex_unlock(&w->wait_ack_buff_mx);
        pthread_mutex_unlock(&m->esc_mx);
    }
}
int worker_recv_packet(worker_t *w, mpudp_packet_t *p)
{
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    mpudp_packet_t *target;

    int res = pcap_next_ex(w->if_handle, &pkt_header, &pkt_data);

    if(res != 1)
        return 0;

    eth_frame_t frame;
    eth_read_frame(&frame, (u_char*)pkt_data, pkt_header->len);

    if(frame.type[0] != 0x08 || frame.type[1] != 0x00)
    {
        return 0;
    }

    ip_packet_t ip_packet;
    ip_read_packet(&ip_packet, frame.data, frame.data_len);

    if(ip_get_proto(&ip_packet) != PROTO_UDP)
    {
        return 0;
    }

    udp_dgram_t udp_dgram;
    udp_read_dgram(&udp_dgram, ip_packet.payload, ip_get_len(&ip_packet));

    res = mpudp_chars2packet(p, udp_dgram.data, udp_dgram.len - UDP_PREFIX_LEN);

    free(frame.data);
    free(ip_packet.payload);
    free(udp_dgram.data);

    if(res == -1)
        return 0;

    if(p->type == MPUDP_DATA || p->type == MPUDP_ACK || p->type == MPUDP_CONFIG)
    {
        return 1;
    }

    return 0;
}

int worker_send(worker_t *w, mpudp_packet_t *p, int type)
{
    eth_frame_t eth_frame;
    ip_packet_t ip_packet;
    udp_dgram_t udp_dgram;

    unsigned char *eth_payload, *ip_payload, *udp_payload;

    /* printf("[%d] - sending packet... %d len: %d\n", w->id, p->id, p->len); */

    int eth_len, ip_len, udp_len;

    if(type == SEND_UCAST)
    {
        eth_build_frame(&eth_frame, w->dst_mac, w->src_mac, ETH_TYPE_IP);
        ip_build_packet(&ip_packet, w->src_ip, w->dst_ip);
        udp_build_dgram_hdr(&udp_dgram, w->src_port, w->dst_port);
    }
    else if(type == SEND_BCAST)
    {
        eth_build_frame(&eth_frame, w->bcast_mac, w->src_mac, ETH_TYPE_IP);
        ip_build_packet(&ip_packet, w->src_ip, w->bcast_ip);
        udp_build_dgram_hdr(&udp_dgram, w->src_port, w->dst_port);
    }

    uint8_t *payload;
    int len = mpudp_packet2chars(p, &payload);
    /* printf("Packet len: %d\n", *(uint32_t*)payload+5); */

    udp_set_data(&udp_dgram, payload, len);
    udp_len = udp_dgram2chars(&udp_dgram, &udp_payload);

    ip_set_data(&ip_packet, udp_payload, udp_len);
    ip_len = ip_packet2chars(&ip_packet, &ip_payload);

    eth_set_data(&eth_frame, ip_payload, ip_len);
    eth_len = eth_frame2chars(&eth_frame, &eth_payload);

    pcap_sendpacket(w->if_handle, eth_payload, eth_len);

    free(udp_dgram.data);
    free(ip_packet.payload);
    free(eth_frame.data);

    free(eth_payload);
    free(ip_payload);
    free(udp_payload);
    free(payload);

    return 0;
}

int worker_send_ack(worker_t *w, uint32_t id)
{
    mpudp_packet_t *ack = malloc(sizeof(mpudp_packet_t));
    ack->type = MPUDP_ACK;
    ack->id   = id;
    ack->len  = 0;

    pthread_mutex_lock(&w->private_tx_buff_mx);
    while(w->private_tx_buff != NULL)
    {
        pthread_cond_wait(&w->tx_empty, &w->private_tx_buff_mx);
    }

    /* printf("[%d] - pushing ack %d\n", w->id, id); */
    w->private_tx_buff = ack;

    pthread_cond_broadcast(&w->tx_ready);
    pthread_mutex_unlock(&w->private_tx_buff_mx);

    return 0;
}

int watchdog_check_state(worker_t *w)
{
    /* printf("[%d] - tx watcher started check\n", w->id); */

    pthread_mutex_lock(&w->wait_ack_buff_mx);
    pthread_mutex_lock(&w->private_tx_buff_mx);
    pthread_mutex_lock(&w->m->esc_mx);

    /* printf("[%d] - tx watcher got locks\n", w->id); */

    int users_data = (w->m->tx_num <= 0);
    int esc_data = (w->m->esc_num <= 0);
    int bcast_data = (w->m->checkin[w->id] == 0);

    int ack_free = w->ack_num >= BUFF_LEN;
    int fetch_user_data = users_data || ack_free;
    int fetch_esc_data  = esc_data   || ack_free;

    int private_tx = w->private_tx_buff != NULL;
    int worker_state = w->state == WORKER_NOT_CONNECTED;

    int has_data = (fetch_user_data && bcast_data && fetch_esc_data);
    int can_send = (private_tx || worker_state);

    /* printf("[%d] - user: %d, bcast %d, esc_data %d, private_tx %d\n", */
    /*         w->id, fetch_user_data, bcast_data, esc_data, private_tx); */

    return has_data || can_send;
}

void* worker_arq_watcher(void *arg)
{
    worker_t  *w = (worker_t*)arg;
    monitor_t *m = w->m;
    struct timeval current_time;
    int difftime_ms;
    int idx;

    int i, oldest;
    int flag = 0;

    mpudp_packet_t *p;

    while(1)
    {
        /* printf("[%d] - ARQ watcher alive\n", w->id); */

        flag = 0;

        if(w->state == WORKER_NOT_CONNECTED)
        {
            printf("[%d] - still not connected\n", w->id);
            sleep(1);
            continue;
        }

        pthread_mutex_lock(&w->wait_ack_buff_mx);

        gettimeofday(&current_time, NULL);

        for(i = 0; i < BUFF_LEN; i++)
        {
            idx = (w->ack_tail + i) % BUFF_LEN;
            /* idx = w->ack_tail; */

            p = w->wait_ack_buff[idx];
            difftime_ms = get_difftime(&current_time, &w->last_send_time[idx]);

            if(p != NULL && (difftime_ms > 5000))
            {
                printf("[%d] - should retransmit %d\n", w->id, p->id);
                flag = 1;

                if(w->arq_count[idx] > 6)
                {
                    printf("[%d] - link is dead!\n", w->id);
                    /* shutdown_worker(w); */
                    pthread_mutex_unlock(&w->wait_ack_buff_mx);
                    reconfigure_workers(m);
                    continue;
                }

                w->arq_count[idx]++;

                pthread_mutex_lock(&w->private_tx_buff_mx);
                while(w->private_tx_buff != NULL)
                {
                    pthread_cond_wait(&w->tx_empty, &w->private_tx_buff_mx);
                }

                gettimeofday(&w->last_send_time[idx], NULL);
                w->private_tx_buff = w->wait_ack_buff[idx];

                pthread_cond_broadcast(&w->tx_ready);
                pthread_mutex_unlock(&w->private_tx_buff_mx);
                break;
            }
        }

        pthread_mutex_unlock(&w->wait_ack_buff_mx);

        if(flag == 0)
            usleep(1000000);
        else
            usleep(10000);
    }
}

int find_empty(mpudp_packet_t **buff)
{
    int i;
    for(i = 0; i < BUFF_LEN; i++)
    {
        if(buff[i] == NULL)
        {
            return i;
        }
    }
}

int find_oldest(worker_t *w)
{
    int min_id = -1;
    int i;

    uint8_t seconds, useconds;
    uint8_t oldest_time = 0;
    uint8_t this_time;

    struct timeval current_time;
    gettimeofday(&current_time, NULL);


    /* dump_ack_buff(buff); */

    for(i = 0; i < BUFF_LEN; i++)
    {
        if(w->wait_ack_buff[i] == NULL)
        {
            continue;
        }
        else if(min_id == -1)
        {
            min_id = i;
        }

        seconds  = current_time.tv_sec  - w->last_send_time[i].tv_sec;
        useconds = current_time.tv_usec - w->last_send_time[i].tv_usec;
        this_time = seconds*1000 + useconds/1000;

        if(this_time > oldest_time)
        {
            oldest_time = this_time;
            min_id = i;
        }
    }

    if(oldest_time < 20)
    {
        return -1;
    }
    else
    {
        return min_id;
    }
}

void dump_ack_buff(mpudp_packet_t **buff)
{
    int i;
    for(i = 0; i < BUFF_LEN; i++)
    {
        if(buff[i] == NULL)
        {
            printf("(null) ");
        }
        else
        {
            printf("%d ", buff[i]->id);
        }
    }

    printf("\n");
}

int get_difftime(struct timeval *current, struct timeval *target)
{
    unsigned long seconds  = current->tv_sec  - target->tv_sec;
    unsigned long useconds = current->tv_usec - target->tv_usec;
    return seconds*1000 + useconds/1000;
}

int slide_window(worker_t *w)
{
    int i;
    mpudp_packet_t *p;
    int retval = 0;

    /* printf("[%d] - started slding\n", w->id); */
    /* dump_ack_buff(w->wait_ack_buff); */

    int old = w->ack_num;

    for(i = 0; i < old; i++)
    {
        p = w->wait_ack_buff[w->ack_tail];

        /* printf("[%d] - tail: %d idx: %d i: %d\n", w->id, w->ack_tail, idx, i); */

        if(p == NULL)
        {
            /* printf("[%d] - go on, I'm on %d\n", w->id, idx); */
            w->ack_tail = (w->ack_tail + 1) % BUFF_LEN;
            w->ack_num--;
            retval = 1;
        }
        else
        {
            break;
        }

        if(w->ack_num == 0)
            return 1;
    }

    return retval;
}

void shutdown_worker(worker_t *w)
{
    int i, idx;
    mpudp_packet_t *p;
    monitor_t *m = w->m;

    pthread_mutex_lock(&m->esc_mx);

    for(i = 0; i < BUFF_LEN; i++)
    {
        idx = (w->ack_tail + i) % BUFF_LEN;
        p = w->wait_ack_buff[idx];
        w->wait_ack_buff[idx] = NULL;


        if(p != NULL)
        {
            /* printf("[%d] - dumping %d\n", w->id, p->id); */

            m->esc_data[m->esc_head] = p;
            m->esc_num++;
            m->esc_head = (m->esc_head + 1) % BUFF_LEN;
        }
    }

    pthread_mutex_lock(&m->tx_mx);
    pthread_cond_broadcast(&m->tx_has_data);
    pthread_mutex_unlock(&m->tx_mx);

    pthread_mutex_unlock(&m->esc_mx);

    w->ack_tail = 0;
    w->ack_head = 0;
    w->ack_num  = 0;

    w->state = WORKER_NOT_CONNECTED;
}
