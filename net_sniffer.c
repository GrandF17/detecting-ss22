#include <math.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdbool.h>

#include "./containers/map.c"

#include "./modules/constants.h"

#include "./modules/tls_lable.c"
#include "./modules/ssh_lable.c"
#include "./modules/deviation.c"
#include "./modules/entropy.c"

#define PACKETS_AMOUNT 10
#define INTERFACE "ens33"

struct thread_args {
    const char *interface;
    const char *client_ip;
};

// =========================================
// variables we will write down to csv file:
size_t min_packet_size;
size_t max_packet_size;
double packet_len_deviation;
double entropy;
double entropy_deviation;
// most representative:
bool udp_lable;
bool tcp_lable;
bool sctp_lable;
// using only port recognition:
bool tls_lable;
bool ssh_lable;

// ==================
// service variables:

// entropy
size_t empty_bits;
size_t filled_bits;

// packet_len_deviation
size_t packet_count;
size_t packet_sizes[PACKETS_AMOUNT];
double packet_entropy[PACKETS_AMOUNT];

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN); // Ethernet header is 14 bytes
    int ip_header_length = ip_header->ip_hl * 4;

    if (ip_header->ip_p == IPPROTO_TCP) tcp_lable = true;
    else if (ip_header->ip_p == IPPROTO_UDP) udp_lable = true;
    else if(ip_header->ip_p == IPPROTO_SCTP) sctp_lable = true;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    // printf("From: %s; to: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

    if(has_tls_lable(header, packet)) tls_lable = true;
    if(has_ssh_lable(header, packet)) ssh_lable = true;
    
    // packet len deviation:
    packet_sizes[packet_count] = header->len;
    // entropy deviation:
    packet_entropy[packet_count] = count_packet_entropy(packet, header->len);
    ++packet_count;

    // min packet len
    if (min_packet_size == 0) {
        min_packet_size = header->len;
    } else {
        min_packet_size =
            min_packet_size < header->len ? min_packet_size : header->len;
    }

    // max packet len
    if (max_packet_size == 0) {
        max_packet_size = header->len;
    } else {
        max_packet_size =
            max_packet_size > header->len ? max_packet_size : header->len;
    }
    
    // total flow entropy:
    for (size_t i = 0; i < header->len; ++i) {
        empty_bits += 8 - bit_count_table[packet[i]];
        filled_bits += bit_count_table[packet[i]];
    }
}

void *listen_on_device(void* args) {
    struct thread_args *thread_data = (struct thread_args *)args;
    const char* device_name = (char *)thread_data->interface;
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
    
    /*while(1)*/ {
        // listen for 10 packets:
        printf("Listening on device: %s\n", device_name);
        pcap_loop(handle, 20, packet_handler, NULL);

        // counting entropy:
        entropy = count_bin_entropy(empty_bits, filled_bits);

        // counting standart packet len deviation:
        packet_len_deviation = count_deviation_generic(packet_sizes, PACKETS_AMOUNT);
        entropy_deviation = count_deviation_generic(packet_entropy, PACKETS_AMOUNT);

        printf("Minimum Packet Size: %zu bytes\n", min_packet_size);
        printf("Maximum Packet Size: %zu bytes\n", max_packet_size);
        printf("Packet Size Standard Deviation: %.4f bytes\n", packet_len_deviation);
        printf("Packet Entropy: %.4f\n", entropy);
        printf("Packet Entropy Deviation: %.4f\n", entropy_deviation);

        printf("Protocols detected: ");
        if(udp_lable) printf("udp ");
        if(tcp_lable) printf("tcp ");
        if(sctp_lable) printf("sctp ");
        if(ssh_lable) printf("ssh ");
        if(tls_lable) printf("tls ");
        printf("\n");
    }

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