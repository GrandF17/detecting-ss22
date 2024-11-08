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

#include "./modules/constants.h"

// =========================

#include "./modules/csv.c"
#include "./modules/deviation.c"
#include "./modules/entropy.c"
#include "./modules/ssh_lable.c"
#include "./modules/tls_lable.c"

// =========================

const char *client_ip;

FlowStat ip_stats[MAX_IP_COUNT];
int ip_count = 0;

int get_stat_idx(const char *ip_address) {
    for (int i = 0; i < ip_count; ++i) {
        if (strcmp(ip_stats[i].rec_ip, ip_address) == 0) {
            return i;
        }
    }

    return -1;
}

int create_stat(const char *ip_address) {
    int ip_id = get_stat_idx(ip_address);
    if (ip_id != -1) {
        memset(&ip_stats[ip_id], 0, sizeof(FlowStat));
        return ip_id;
    }

    // if ip was not found --> add new one
    if (ip_count < MAX_IP_COUNT) {
        strcpy(ip_stats[ip_count].rec_ip, ip_address);
        return ip_count++;
    }

    return -1;
}

//////////////////////////////

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN);  // Ethernet header is 14 bytes
    int ip_header_length = ip_header->ip_hl * 4;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    const char *remote_ip = strcmp(src_ip, client_ip) == 0 ? dst_ip : src_ip;
    int id = get_stat_idx(remote_ip);
    FlowStat *session;

    if (id == -1) {
        session = &ip_stats[create_stat(remote_ip)];
    } else {
        session = &ip_stats[id];
    }

    // if there are already enough packets for current session
    if (session->packet_count == PACKETS_AMOUNT - 1) {
        // counting standart packet len deviation:
        session->packet_len_deviation = count_deviation_generic(session->packet_sizes, PACKETS_AMOUNT);
        session->entropy_deviation = count_deviation_generic(session->packet_entropy, PACKETS_AMOUNT);

        appendCSV("data.csv", session);
        logCSV(session);

        session = &ip_stats[create_stat(remote_ip)];
    }

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
    session->packet_sizes[session->packet_count] = header->len;
    // entropy deviation:
    session->packet_entropy[session->packet_count] = count_packet_entropy(packet, header->len);
    ++session->packet_count;

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
    pcap_loop(handle, 100, packet_handler, NULL);
    pcap_close(handle);

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <CLIENT_IP_ADDRESS>\n", argv[0]);
        return 1;
    }

    client_ip = argv[1];

    listen_on_device();

    return 0;
}