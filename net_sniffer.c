#include <arpa/inet.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>

// =========================
#include "./constants.h"

// =========================
#include "./libs/head/dynamic_flow_stats.h"
#include "./libs/head/dynamic_double.h"
#include "./libs/head/dynamic_size_t.h"

// =========================
#include "./modules/finalize.c"
#include "./modules/deviation.c"
#include "./modules/entropy.c"
#include "./modules/ssh_lable.c"
#include "./modules/tls_lable.c"
#include "./modules/csv.c"

const char *client_ip;
FlowStatArray ip_stats;

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN);  // Ethernet header is 14 bytes

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // detecting interaction ip
    const char *remote_ip = strcmp(src_ip, client_ip) == 0 ? dst_ip : src_ip;
    printf("remote_ip: %s\n", remote_ip);

    // time
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    // // run through all written ips and checking last update time
    // for (size_t i = 0; i < ip_stats.count; ++i) {
    //     // printf("Last upd: %.4f, now: %.4ld\n", ip_stats.array[i].last_upd, now.tv_sec);
    //     if(ip_stats.array[i].start != 0 && ip_stats.array[i].last_upd + 5 /** seconds */ < now.tv_sec) {
    //         // set last
    //         finalize_flow(&ip_stats.array[i]);
    //         create_stat(&ip_stats, ip_stats.array[i].rec_ip);
    //     }
    // }

    FlowStat *session;

    // get stats for current remote_ip
    int idx = get_stat_idx(&ip_stats, remote_ip);
    if (idx != -1) {
        session = &ip_stats.array[idx];
    } else {
        session = &ip_stats.array[create_stat(&ip_stats, remote_ip)];
    }

    if(session->start != 0 && session->last_upd + 5 /** seconds */ < now.tv_sec) {
        printf("finalizing for %s\n", remote_ip);
        finalize_flow(session);
        create_stat(&ip_stats, session->rec_ip);
    }

    // counting server/client packets passed to each other
    if(strcmp(src_ip, client_ip) == 0) {
        ++session->client_pckt_amount;
    } else {
        ++session->server_pckt_amount;
    }

    if(session->start == 0) {
        session->start = now.tv_sec;
    }
    session->last_upd = now.tv_sec;

    // detecting ip protos
    if (ip_header->ip_p == IPPROTO_TCP) {
        session->tcp_lable = true;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        session->udp_lable = true;
    } else if (ip_header->ip_p == IPPROTO_SCTP) {
        session->sctp_lable = true;
    }

    // detecting secure protos
    if (has_tls_lable(header, packet)) {
        session->tls_lable = true;
    }
    if (has_ssh_lable(header, packet)) {
        session->ssh_lable = true;
    }

    // packet len deviation:
    push_back_size_t(&session->packet_sizes, header->len);
    // entropy deviation:
    push_back_double(&session->packet_entropy, count_packet_entropy(packet, header->len));

    // min packet len
    if (session->min_packet_size == 0) {
        session->min_packet_size = header->len;
    } else {
        session->min_packet_size =
            session->min_packet_size < header->len ? session->min_packet_size : header->len;
    }

    // max packet len
    if (session->max_packet_size == 0) {
        session->max_packet_size = header->len;
    } else {
        session->max_packet_size =
            session->max_packet_size > header->len ? session->max_packet_size : header->len;
    }

    // total flow entropy:
    for (size_t i = 0; i < header->len; ++i) {
        session->empty_bits += 8 - bit_count_table[packet[i]];
        session->filled_bits += bit_count_table[packet[i]];
    }
}

void *listen_on_device() {
    char filter_exp[50];
    char errbuf[PCAP_ERRBUF_SIZE];

    // creating client oriented filter:
    snprintf(filter_exp, sizeof(filter_exp), "host %s", client_ip);

    // opening interface to capture
    pcap_t *handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %sn", INTERFACE, errbuf);
        return NULL;
    }

    // setting up filter
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %sn", filter_exp, pcap_geterr(handle));
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %sn", filter_exp, pcap_geterr(handle));
        return NULL;
    }

    printf("Listening on device: %s\n", INTERFACE);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <CLIENT_IP_ADDRESS>\n", argv[0]);
        return 1;
    }

    client_ip = argv[1];
    init_flow_stat_array(&ip_stats, 10);

    listen_on_device();

    free_flow_stat_array(&ip_stats);
    return 0;
}