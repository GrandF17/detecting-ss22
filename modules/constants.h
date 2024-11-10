#ifndef SNIFFER_MODULES_CONSTANTS_H_INCLUDED
#define SNIFFER_MODULES_CONSTANTS_H_INCLUDED

#include <arpa/inet.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_IP_COUNT 100

#define ETHERNET_HEADER_LEN 14
#define PACKETS_AMOUNT 10
#define INTERFACE "ens33"

typedef struct {
    char rec_ip[INET_ADDRSTRLEN];
    // =========================================
    // variables we will write down to csv file:
    double average_waiting_time;
    double total_time;
    size_t client_pckt_amount;
    size_t server_pckt_amount;

    size_t min_packet_size;
    size_t max_packet_size;
    double packet_len_deviation;
    double entropy;
    double entropy_deviation;
    // most representative:
    bool udp_lable;
    bool tcp_lable;
    bool sctp_lable;
    // using only port and basic points recognition:
    bool tls_lable;
    bool ssh_lable;

    // ==================
    // service variables:

    size_t packet_count;

    // entropy
    size_t empty_bits;
    size_t filled_bits;
    double packet_entropy[PACKETS_AMOUNT];

    // packet_len_deviation
    size_t packet_sizes[PACKETS_AMOUNT];

    // time
    double start;
    double end;
} FlowStat;

typedef struct {
    FlowStat *array;
    size_t count;
    size_t capacity;
} FlowStatArray;

#endif