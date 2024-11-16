#ifndef SNIFFER_MODULES_CONSTANTS_H_INCLUDED
#define SNIFFER_MODULES_CONSTANTS_H_INCLUDED

#include <arpa/inet.h>
#include <stddef.h>
#include <stdbool.h>

#define ETHERNET_HEADER_LEN 14  // Ethernet header is 14 bytes
#define ARP_PROTOCOL 0x0806     // ARP protocol 

#define PACKETS_AMOUNT 10
#define INTERFACE "ens33"       // default interface on Ubuntu 24 to listen


struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_addr_len;
    uint8_t proto_addr_len;
    uint16_t operation;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

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
    bool range_of_six;         // first n > 6 bytes are in range [0x20, 0x7e]
    bool range_of_half;        // more than a half of bytes is in range [0x20, 0x7e]
    bool range_seq;    // more than 20 bytes are in range [0x20, 0x7e]
    bool is_http_or_tls;
} FirstPacket;

typedef struct {
    char rec_ip[INET_ADDRSTRLEN];
    // =========================================
    // variables we will write down to csv file:
    FirstPacket first_pct_stat;

    double entropy;
    double std_pckt_size;
    size_t q1_pckt_size;
    size_t q2_pckt_size;
    size_t q3_pckt_size;
    size_t iqr_pckt_size;
    double pckt_size_outliers;

    double std_entropy;
    double q1_entropy;
    double q2_entropy;
    double q3_entropy;
    double iqr_entropy;
    double entropy_outliers;

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

    long long total_time;
    long long avg_waiting_time;
    size_t client_pckt_amount;
    size_t server_pckt_amount;
    size_t min_pckt_size;
    size_t max_pckt_size;
    size_t keep_alive_pckt_amount;

    // ==================
    // service variables:

    // entropy
    size_t empty_bits;
    size_t filled_bits;

    // rows of each packet metrics
    DoubleArray packet_entropy;
    SizeTArray packet_sizes;

    // timestamps
    long long start;
    long long last_upd;
} FlowStat;

typedef struct {
    FlowStat *array;
    size_t count;
    size_t capacity;
} FlowStatArray;

#endif