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

#include "./modules/constants.h"

#include "./modules/tls_lable.c"
#include "./modules/ssh_lable.c"
#include "./modules/deviation.c"
#include "./modules/entropy.c"

#define PACKETS_AMOUNT 50
#define INTERFACE "ens33"

char *client_ip;
char *server_ip;

// =========================================
// variables we will write down to csv file:
size_t client_server_packets_amount[2];
size_t min_packet_size;
size_t max_packet_size;
double packet_len_deviation;
double entropy;
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
size_t packet_sizes[PACKETS_AMOUNT];
size_t packet_count;

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN); // Ethernet header is 14 bytes
    int ip_header_length = ip_header->ip_hl * 4;

    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_lable = true;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        udp_lable = true;
    } else if(ip_header->ip_p == IPPROTO_SCTP) {
        sctp_lable = true;
    }

    tls_lable = has_tls_lable(header, packet);
    ssh_lable = has_ssh_lable(header, packet);
    
    // if(
    //     strncmp(inet_ntoa(ip_header->ip_src), client_ip, ip_header->ip_id) == 0 &&
    //     strncmp(inet_ntoa(ip_header->ip_dst), server_ip, ip_header->ip_id) == 0
    // ) {
    //     // printf("Src: %s\n", inet_ntoa(ip_header->ip_src));
    //     // printf("Dst: %s\n", inet_ntoa(ip_header->ip_dst));
    //     // printf("Client: %s\n", client_ip);
    //     // printf("Server: %s\n", server_ip);
    //     // printf("Header len: %d\n", ip_header->ip_id);

    //     ++client_server_packets_amount[0];
    // } else if(
    //     strncmp(inet_ntoa(ip_header->ip_src), server_ip, ip_header->ip_id) == 0 &&
    //     strncmp(inet_ntoa(ip_header->ip_dst), client_ip, ip_header->ip_id) == 0
    // ) {
    //     ++client_server_packets_amount[1];
    // }

    // for tcp:
    // inet_ntoa(ip_header->ip_src), ntohs(tcp_header->source)
    // inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->dest)
    // for udp:
    // struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header_length);
    // inet_ntoa(ip_header->ip_src), ntohs(udp_header->source)
    // inet_ntoa(ip_header->ip_dst), ntohs(udp_header->dest)
    
    // for standart packet len deviation:
    packet_sizes[packet_count] = header->len;
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

    // entropy
    for (size_t i = 0; i < header->len; ++i) {
        empty_bits += 8 - bit_count_table[packet[i]];
        filled_bits += bit_count_table[packet[i]];
    }
}

void *listen_on_device(void *device_name) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live((char *)device_name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open device %s: %s\n", (char *)device_name, error_buffer);
        return NULL;
    }

    /*while(1)*/ {
        // listen for 10 packets:
        printf("Listening on device: %s\n", (char *)device_name);
        pcap_loop(handle, PACKETS_AMOUNT, packet_handler, NULL);

        // counting entropy:
        entropy = count_bin_entropy(empty_bits, filled_bits);

        // counting standart packet len deviation:
        packet_len_deviation = count_deviation(packet_sizes, PACKETS_AMOUNT);

        printf("Client Passed: %zu packets\n", client_server_packets_amount[0]);
        printf("Server Passed: %zu packets\n", client_server_packets_amount[0]);
        printf("Minimum Packet Size: %zu bytes\n", min_packet_size);
        printf("Maximum Packet Size: %zu bytes\n", max_packet_size);
        printf("Packet Size Standard Deviation: %.4f bytes\n", packet_len_deviation);
        printf("Packet Entropy: %.4f\n", entropy);

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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <client_ip> <server_ip>n", argv[0]);
        return 1;
    }

    client_ip = argv[1];
    server_ip = argv[2];

    // Создаем фильтр для захвата пакетов от клиента к серверу и от сервера к клиенту
    char filter_exp[200];
    snprintf(filter_exp, sizeof(filter_exp), "ip host %s and (ip dst %s or ip src %s)", client_ip, server_ip, server_ip);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Открываем интерфейс для захвата
    handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %sn", INTERFACE, errbuf);
        return 1;
    }

    // Устанавливаем фильтр
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %sn", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %sn", filter_exp, pcap_geterr(handle));
        return 1;
    }

    pthread_t thread;

    if (pthread_create(&thread, NULL, listen_on_device, (void *)INTERFACE) != 0) {
        fprintf(stderr, "Error creating thread for device %s\n", INTERFACE);
        return 1;
    }

    pthread_join(thread, NULL);

    return 0;
}