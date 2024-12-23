#ifndef SNIFFER_MODULES_IS_SSH_label_C_INCLUDED
#define SNIFFER_MODULES_IS_SSH_label_C_INCLUDED

#include <pcap.h>
#include <string.h>
#include <stdbool.h>

#include "../constants.h"

// SSH signs
#define SSH_PORT 22
#define SSH_PREFIX "SSH-"

bool has_ssh_label(const struct pcap_pkthdr *header, const uint8_t *packet) {
    if (header->caplen < 54) {
        return false;
    }

    // offset until tcp header
    const uint8_t *ip_header = packet + ETHERNET_HEADER_LEN;
    uint8_t ip_header_length = (ip_header[0] & 0x0F) * 4;

    const uint8_t *tcp_header = ip_header + ip_header_length;
    uint16_t source_port = (tcp_header[0] << 8) | tcp_header[1];
    uint16_t dest_port = (tcp_header[2] << 8) | tcp_header[3];

    // check SSH port (frequently 22)
    if (source_port != SSH_PORT && dest_port != SSH_PORT) {
        return false;
    }

    // offset until tcp payload
    uint8_t tcp_header_length = ((tcp_header[12] & 0xF0) >> 4) * 4;
    const uint8_t *tcp_payload = tcp_header + tcp_header_length;

    // check for ssh prefix "SSH-"
    if (memcmp(tcp_payload, SSH_PREFIX, strlen(SSH_PREFIX)) == 0) {
        return true;
    }

    return false;
}

#endif