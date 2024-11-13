#ifndef SNIFFER_MODULES_HTTP_LABLE_C_INCLUDED
#define SNIFFER_MODULES_HTTP_LABLE_C_INCLUDED

#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define HTTP_SIGNATURES_COUNT 12

const char *http_signatures[HTTP_SIGNATURES_COUNT] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
    "PATCH", "CONNECT", "TRACE", "HTTP/1.0", "HTTP/1.1", "HTTP/2"
};

bool has_http_lable(const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ether_header *eth = (struct ether_header *)packet;

    // check if it's IPv4
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return false;

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    // check if it's TCP
    if (ip_header->ip_p != IPPROTO_TCP) return false;
        
    size_t ip_header_length = ip_header->ip_hl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *)((uint8_t *)ip_header + ip_header_length);

    // getting ports
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    // check if ports are equal to HTTP ports (80)
    if (src_port != 80 &&dst_port != 80) return false;

    size_t tcp_header_length = tcp_header->th_off * 4;
    const uint8_t *payload = (const uint8_t *)((uint8_t *)tcp_header + tcp_header_length);

    int payload_length = ntohs(ip_header->ip_len) - (ip_header_length + tcp_header_length);
    if (payload_length > 0) {
        for (int i = 0; i < HTTP_SIGNATURES_COUNT; i++) {
            if (strncmp((const char *)payload, http_signatures[i], strlen(http_signatures[i])) == 0) {
                return true;
            }
        }
    }
    return false;
}

#endif