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

#include "./containers/map.c"

// =========================

#include "./modules/csv.c"
#include "./modules/deviation.c"
#include "./modules/entropy.c"
#include "./modules/ssh_lable.c"
#include "./modules/tls_lable.c"

// =========================

struct thread_args {
    const char *interface;
    const char *client_ip;
};

// free function for a FlowStat
void free_data(void *value) {
    free((FlowStat *)value);
}
Map *interaction_map = create_map(free_data);

//////////////////////////////

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN);  // Ethernet header is 14 bytes
    int ip_header_length = ip_header->ip_hl * 4;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    const char *remote_ip = strcmp(src_ip, client_ip) == 0 ? dst_ip : src_ip;
    FlowStat *session;

    if (map_get(interaction_map, remote_ip) == NULL) {
        session = (FlowStat *)malloc(sizeof(FlowStat));
    } else {
        session = map_get(interaction_map, remote_ip);
    }

    // if there are already enough packets for current session
    if (session->packet_count == PACKETS_AMOUNT - 1) {
        // counting standart packet len deviation:
        session->packet_len_deviation = count_deviation_generic(session->packet_sizes, PACKETS_AMOUNT);
        session->entropy_deviation = count_deviation_generic(session->packet_entropy, PACKETS_AMOUNT);

        appendCSV(session);
        log(session);

        map_remove(interaction_map, remote_ip);
        session = (FlowStat *)malloc(sizeof(FlowStat));
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
        fsession->filled_bits += bit_count_table[packet[i]];
    }

    // incerting all changed data:
    map_insert(interaction_map, remote_ip, (void *)&session);
}

void *listen_on_device(void *args) {
    struct thread_args *thread_data = (struct thread_args *)args;
    const char *device_name = (char *)thread_data->interface;
    const char *client_ip = (char *)thread_data->client_ip;

    char filter_exp[50];
    char errbuf[PCAP_ERRBUF_SIZE];

    // creating client oriented filter:
    snprintf(filter_exp, sizeof(filter_exp), "host %s", client_ip);

    // opening interface to capture
    pcap_t *handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %sn", device_name, errbuf);
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

    printf("Listening on device: %s\n", device_name);
    pcap_loop(handle, 100, packet_handler, NULL);
    pcap_close(handle);

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <CLIENT_IP_ADDRESS>\n", argv[0]);
        return 1;
    }

    struct thread_args args;
    args.interface = INTERFACE;
    args.client_ip = argv[1];

    listen_on_device((void *)&args);

    return 0;
}