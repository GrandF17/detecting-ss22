#ifndef SNIFFER_MODULES_CONSTANTS_H_INCLUDED
#define SNIFFER_MODULES_CONSTANTS_H_INCLUDED

#include <arpa/inet.h>
#include <stddef.h>
#include <stdbool.h>

#define ETHERNET_HEADER_LEN 14  // Ethernet header is 14 bytes
#define ARP_PROTOCOL 0x0806     // ARP protocol 

#define PACKETS_AMOUNT 10
#define INTERFACE "ens33"       // default interface on Ubuntu 24 to listen

// app modes:
#define COLLECT_SS22 "collect_ss22"
#define COLLECT_LEGITIMATE_TRAFFIC "collect_lt"
#define BROADCAST "broadcast"

#define BUFFER_SIZE 1024

// headers
#define FIRST_PCT "first_pckt_entropy,range_of_six,range_of_half,range_seq,is_http_or_tls"
#define ENTROPY "entropy"
#define STAT_PCKT_SIZES "std_pckt_size,q1_pckt_size,q2_pckt_size,q3_pckt_size,iqr_pckt_size,pckt_size_outliers_lb,pckt_size_outliers_ub"
#define STAT_ENTROPY "std_entropy,q1_entropy,q2_entropy,q3_entropy,iqr_entropy,entropy_outliers_lb,entropy_outliers_ub"
#define PROTO_LABELS "udp_label,tcp_label,sctp_label,http_label,tls_label,ssh_label"
#define OTHER_METRICS "total_time,avg_waiting_time,client_pckt_amount,server_pckt_amount,min_pckt_size,max_pckt_size,keep_alive_pckt_amount"
#define IS_SS22 "is_ss22"

/* here you can INSERT your own headers for metrics */
#define CSV_HEAD FIRST_PCT "," ENTROPY "," STAT_PCKT_SIZES "," STAT_ENTROPY "," PROTO_LABELS "," OTHER_METRICS "," IS_SS22 "\n"
/* here you can INSERT your own headers for metrics */
#define CSV_BROADCAST FIRST_PCT "," ENTROPY "," STAT_PCKT_SIZES "," STAT_ENTROPY "," PROTO_LABELS "," OTHER_METRICS "\n"

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
    bool range_of_six;         // first n > 6 bytes are in range [0x20,0x7e]
    bool range_of_half;        // more than a half of bytes is in range [0x20,0x7e]
    bool range_seq;    // more than 20 bytes are in range [0x20,0x7e]
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
    size_t pckt_size_outliers_lb;
    size_t pckt_size_outliers_ub;

    double std_entropy;
    double q1_entropy;
    double q2_entropy;
    double q3_entropy;
    double iqr_entropy;
    size_t entropy_outliers_lb;
    size_t entropy_outliers_ub;

    // using only port and basic points recognition:
    // more representative:
    bool udp_label;
    bool tcp_label;
    bool sctp_label;
    // less representative:
    // false positives are likely
    bool http_label;
    bool tls_label;
    bool ssh_label;

    long long total_time;
    long long avg_waiting_time;
    size_t client_pckt_amount;
    size_t server_pckt_amount;
    size_t min_pckt_size;
    size_t max_pckt_size;
    size_t keep_alive_pckt_amount;

    /* here you can INSERT your own metrics variables */

    // ...
    
    /* here you can INSERT your own metrics variables */


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


// math statstics Structs:

// Q1,Q2,Q3,IQR 
typedef struct {
    double Q1;
    double Q2; // median
    double Q3;
    double IQR;
} QuartileResultDouble;

// Q1,Q2,Q3,IQR 
typedef struct {
    size_t Q1;
    size_t Q2; // median
    size_t Q3;
    size_t IQR;
} QuartileResultSizeT;

#endif