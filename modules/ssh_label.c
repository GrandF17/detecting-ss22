#ifndef SNIFFER_MODULES_IS_SSH_label_C_INCLUDED
#define SNIFFER_MODULES_IS_SSH_label_C_INCLUDED

#include <pcap.h>
#include <string.h>
#include <regex.h>
#include <stdbool.h>
#include <ctype.h>

#include "../constants.h"

bool is_ssh_kex(const uint8_t *payload) {
    regex_t regex;
    int reti;

    /* nDPI implementation: */
    // const ssh_pattern ssh_servers_strings[] =
    // {
    //  { (const char*)"SSH-%*f-OpenSSH_%d.%d.%d", 7, 0, 0 },     /* OpenSSH */
    //  { (const char*)"SSH-%*f-APACHE-SSHD-%d.%d.%d", 2, 5, 1 }, /* Apache MINA SSHD */
    //  { (const char*)"SSH-%*f-FileZilla_%d.%d.%d", 3, 40, 0 },  /* FileZilla SSH*/
    //  { (const char*)"SSH-%*f-paramiko_%d.%d.%d", 2, 4, 0 },    /* Paramiko SSH */
    //  { (const char*)"SSH-%*f-dropbear_%d.%d", 2020, 0, 0 },    /* Dropbear SSH */
    //  { NULL, 0, 0, 0 } 
    // };

    const char *pattern = 
    "SSH-[0-9]+\\.[0-9]+-"
    "(OpenSSH_[0-9]+\\.[0-9]+(p[0-9]+)?|"   /* OpenSSH */
    "APACHE-SSHD-[0-9]+\\.[0-9]+\\.[0-9]+|" /* Apache MINA SSHD */
    "FileZilla_[0-9]+\\.[0-9]+\\.[0-9]+|"   /* FileZilla SSH*/
    "paramiko_[0-9]+\\.[0-9]+\\.[0-9]+|"    /* Paramiko SSH */
    "dropbear_[0-9]+\\.[0-9]+)";            /* Dropbear SSH */

    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) {
        perror("Compilation error of regex");
        exit(EXIT_FAILURE);
    }

    reti = regexec(&regex, (const char *)payload, 0, NULL, 0);
    bool is_kex = false;
    if (!reti) is_kex = true;

    regfree(&regex);
    return is_kex;
}

bool has_ssh_label(IP_PortArray *ip_port, const struct pcap_pkthdr *header, const uint8_t *packet) {
    if (header->caplen < 54) {
        return false;
    }

    // offset until ip header
    const uint8_t *ip_header = packet + ETHERNET_HEADER_LEN;
    uint8_t ip_header_length = (ip_header[0] & 0x0F) * 4;

    // Извлечение IP адресов
    uint32_t ip_src = (ip_header[12] << 24) | (ip_header[13] << 16) | (ip_header[14] << 8) | ip_header[15];
    uint32_t ip_dst = (ip_header[16] << 24) | (ip_header[17] << 16) | (ip_header[18] << 8) | ip_header[19];

    const uint8_t *tcp_header = ip_header + ip_header_length;
    uint16_t source_port = (tcp_header[0] << 8) | tcp_header[1];
    uint16_t dest_port = (tcp_header[2] << 8) | tcp_header[3];

    // offset until tcp payload
    uint8_t tcp_header_length = ((tcp_header[12] & 0xF0) >> 4) * 4;
    const uint8_t *tcp_payload = tcp_header + tcp_header_length;

    // extracting TCP flags
    uint8_t tcp_flags = tcp_header[13];

    if (
        (tcp_flags & 0x01 || tcp_flags & 0x04) && // FIN || RST
        contains_ip_port(ip_port, ip_dst, dest_port)
    ) { remove_ip_port(ip_port, ip_dst, dest_port); }

    if (
        (tcp_flags & 0x01 || tcp_flags & 0x04) && // FIN || RST
        contains_ip_port(ip_port, ip_src, source_port)
    ) { remove_ip_port(ip_port, ip_src, source_port); }

    bool isSSH = is_ssh_kex(tcp_payload);

    if (isSSH) { push_back_ip_port(ip_port, ip_src, dest_port); }  
    if (!isSSH && contains_ip_port(ip_port, ip_src, dest_port)) { isSSH = true; }

    return isSSH;
}

#endif