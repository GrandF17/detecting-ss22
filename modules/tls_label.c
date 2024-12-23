#ifndef SNIFFER_MODULES_IS_TLS_LABEL_C_INCLUDED
#define SNIFFER_MODULES_IS_TLS_LABEL_C_INCLUDED

#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "../constants.h"

// TLS msg types
#define TLS_CHANGE_CIPHER_SPEC 0x14
#define TLS_ALERT 0x15
#define TLS_HANDSHAKE 0x16
#define TLS_APPLICATION_DATA 0x17

// TLS version
#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_1 0x0302
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

// Handshake
#define CLIENT_HELLO 0x01
#define SERVER_HELLO 0x02

bool has_tls_label(const struct pcap_pkthdr *header, const char *packet) {
    if (header->caplen < 54) {
        return false;
    }
    
    // offcet until tcp header
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN);
    int ip_header_length = ip_header->ip_hl * 4;

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_length);
    int tcp_header_length = tcp_header->doff * 4;
    const u_char *tcp_payload = packet + ETHERNET_HEADER_LEN + ip_header_length + tcp_header_length;

    uint8_t tls_type = tcp_payload[0];
    if (tls_type != TLS_HANDSHAKE && tls_type != TLS_ALERT && 
        tls_type != TLS_CHANGE_CIPHER_SPEC && tls_type != TLS_APPLICATION_DATA) {
        return false;
    }

    uint16_t tls_version = (tcp_payload[1] << 8) | tcp_payload[2];
    if (tls_version != TLS_VERSION_1_0 && tls_version != TLS_VERSION_1_1 &&
        tls_version != TLS_VERSION_1_2 && tls_version != TLS_VERSION_1_3) {
        return false;
    }

    uint16_t tls_length = (tcp_payload[3] << 8) | tcp_payload[4];
    if (tls_length > header->caplen - 54) {
        return false;
    }

    if (tls_type == TLS_HANDSHAKE) {
        uint8_t handshake_type = tcp_payload[5];
        if (handshake_type != CLIENT_HELLO && handshake_type != SERVER_HELLO) {
            return false;
        }

        uint32_t handshake_length = (tcp_payload[6] << 16) | (tcp_payload[7] << 8) | tcp_payload[8];
        if (handshake_length + 9 > tls_length) {
            return false;
        }
    }

    return true;
}

#endif