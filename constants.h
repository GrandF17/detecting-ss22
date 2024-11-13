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
    double entropy;
    bool correct_range_six;         // first n > 6 bytes are in range [0x20, 0x7e]
    bool correct_range_half;        // more than a half of bytes is in range [0x20, 0x7e]
    bool correct_range_sequence;    // more than 20 bytes are in range [0x20, 0x7e]
    bool is_http_or_tls;
} FirstPacket;

typedef struct {
    char rec_ip[INET_ADDRSTRLEN];
    // =========================================
    // variables we will write down to csv file:
    FirstPacket first_pct_stat;
    
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
    bool http_lable;
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
    size_t start;
    size_t last_upd;
} FlowStat;

typedef struct {
    FlowStat *array;
    size_t count;
    size_t capacity;
} FlowStatArray;

#endif