#ifndef SNIFFER_MODULES_CONSTANTS_H_INCLUDED
#define SNIFFER_MODULES_CONSTANTS_H_INCLUDED

#include <arpa/inet.h>
#include <stddef.h>
#include <stdbool.h>

#define ETHERNET_HEADER_LEN 14   // Ethernet header is 14 bytes
#define PACKETS_AMOUNT 10
#define INTERFACE "ens33"       /// default interface on Ubuntu 24 to listen

typedef struct {
    double *array;
    size_t count;
    size_t capacity;
} DoubleArray;

typedef struct {
    size_t *array;
    size_t count;
    size_t capacity;
} SizeTArray;

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
    double packet_size_deviation;
    double entropy;
    double entropy_deviation;

    // using only port and basic points recognition:
    // more representative:
    bool udp_lable;
    bool tcp_lable;
    bool sctp_lable;
    // less representative:
    // false positives are likely
    bool tls_lable;
    bool ssh_lable;

    // ==================
    // service variables:

    // entropy
    size_t empty_bits;
    size_t filled_bits;
    DoubleArray packet_entropy;

    // packet_size_deviation
    SizeTArray packet_sizes;

    // time
    double start;
    double last_upd;
} FlowStat;

typedef struct {
    FlowStat *array;
    size_t count;
    size_t capacity;
} FlowStatArray;

#endif