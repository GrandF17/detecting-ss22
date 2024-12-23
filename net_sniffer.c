#include <arpa/inet.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <signal.h>

// =========================
#include "./constants.h"

// =========================
#include "./libs/head/dynamic_flow_stats.h"
#include "./libs/head/dynamic_double.h"
#include "./libs/head/dynamic_size_t.h"

// =========================
#include "./modules/ranges_counter.c"
#include "./modules/finalize.c"
#include "./modules/deviation.c"
#include "./modules/entropy.c"
#include "./modules/http_label.c"
#include "./modules/ssh_label.c"
#include "./modules/tls_label.c"

#include "./modules/websocket.c"
#include "./modules/time.c"
#include "./modules/csv.c"

FlowStatArray ip_stats;

const int *session_split_delay; // in seconds
const char *client_ip;          // fixed client ip to watch
const char *mode;               // collect/broadcast


bool first_time_met_tcp(const FirstPacket *packet) {
    return packet->entropy == 0.0 &&
           !packet->range_of_six &&
           !packet->range_of_half &&
           !packet->range_seq &&
           !packet->is_http_or_tls;
}


// -==================================- //
// -=============- PCAP -=============- //

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ethernet_header *eth_hdr = (struct ethernet_header *)packet;

    if (ntohs(eth_hdr->ethertype) == ARP_PROTOCOL) {
        // printf("ARP packet handled.\n");
        return;
    }

    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // detecting interaction ip
    const char *remote_ip = strcmp(src_ip, client_ip) == 0 ? dst_ip : src_ip;
    // find or init session for current remoute ip
    int idx = get_stat_idx(&ip_stats, remote_ip);
    FlowStat *session;

    if (idx == -1) {
        int newIdx = create_stat(&ip_stats, remote_ip);
        if(newIdx == -1) {
            printf("ERROR (create_stat)!!!\n");
            exit(1);
        }
        session = &ip_stats.array[newIdx];
    } else { session = &ip_stats.array[idx]; }

    // finalize session, if delay between latest and 
    // current packets more than 'session_split_delay'
    if(session->start != 0 && session->last_upd + *session_split_delay * 1000 < milliseconds()) {
        finalize_flow(session, mode);
        create_stat(&ip_stats, session->rec_ip);
    }

    // counting server/client packets passed to each other
    if(strcmp(src_ip, client_ip) == 0) { ++session->client_pckt_amount; } 
    else { ++session->server_pckt_amount; }

    // time record
    if(session->start == 0) { session->start = milliseconds(); }
    session->last_upd = milliseconds();

    // detecting ip protos
    if (ip_header->ip_p == IPPROTO_TCP) {
        if(first_time_met_tcp(&session->first_pct_stat)) {
            session->first_pct_stat.entropy = count_packet_entropy(packet, header->len);
            session->first_pct_stat.range_of_six = check_first_six_bytes(packet, header->len);
            session->first_pct_stat.range_of_half = check_more_than_50_percent(packet, header->len);
            session->first_pct_stat.range_seq = check_more_than_20_contiguous(packet, header->len);
            session->first_pct_stat.is_http_or_tls = has_tls_label(header, packet) || has_http_label(header, packet); 
        }

        session->tcp_label = true;
    } 
    else if (ip_header->ip_p == IPPROTO_UDP) { session->udp_label = true; } 
    else if (ip_header->ip_p == IPPROTO_SCTP) { session->sctp_label = true; }

    // detecting secure protos
    if (has_tls_label(header, packet)) session->tls_label = true;
    if (has_ssh_label(header, packet)) session->ssh_label = true;
    if (has_http_label(header, packet)) session->http_label = true;

    // collecting each packet len data
    push_back_size_t(&session->packet_sizes, header->len);
    // collecting each packet entropy data
    push_back_double(&session->packet_entropy, count_packet_entropy(packet, header->len));

    // min packet len
    if (session->min_pckt_size == 0) {
        session->keep_alive_pckt_amount = 1;
        session->min_pckt_size = header->len;
    } else {
        if(header->len < session->min_pckt_size) {
            session->keep_alive_pckt_amount = 1;
            session->min_pckt_size = header->len;
        } else if(header->len == session->min_pckt_size) {
            ++session->keep_alive_pckt_amount;
        }
    }

    // max packet len
    if (session->max_pckt_size == 0) {
        session->max_pckt_size = header->len;
    } else {
        session->max_pckt_size = session->max_pckt_size > header->len 
            ? session->max_pckt_size 
            : header->len;
    }

    // collecting amount of filled and empty bits
    // for total flow per session
    for (size_t i = 0; i < header->len; ++i) {
        session->empty_bits += 8 - bit_count_table[packet[i]];
        session->filled_bits += bit_count_table[packet[i]];
    }

    /* here you can INSERT your own metrics to collect */

    // ...

    /* here you can INSERT your own metrics to collect */
}

void *listen_on_device() {
    char filter_exp[50];
    char errbuf[PCAP_ERRBUF_SIZE];

    // creating client oriented filter:
    snprintf(filter_exp, sizeof(filter_exp), "host %s", client_ip);

    // opening interface to capture
    pcap_t *handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %sn", INTERFACE, errbuf);
        return NULL;
    }

    // setting up filter
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %sn", filter_exp, pcap_geterr(handle));
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %sn", filter_exp, pcap_geterr(handle));
        return NULL;
    }

    printf("Listening on device: %s\n", INTERFACE);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return NULL;
}

// smart programm interruption
void signal_handler(int signum) {
    printf("\nCaught signal %d (e.g., Ctrl+C). Executing cleanup...\n", signum);

    // running through all 'ip_stats' and recording them to .csv...

    // programm complete
    exit(0);
}


int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    if (argc != 4) {
        fprintf(stderr, "Usage: sudo %s <CLIENT_IP_ADDRESS> <SESSION_SPLIT_DELAY> <MODE>\n", argv[0]);
        fprintf(stderr, "CLIENT_IP_ADDRESS - ip str you want to watch after\n");
        fprintf(stderr, "SESSION_SPLIT_DELAY - interval in seconds that allows to split sessions for 2 current ips\n");
        fprintf(stderr, "MODE:\n");
        fprintf(stderr, "\t - 'collect_ss22' affords to collect !shadowsocks22! traffic metrics for all ips connceted to CLIENT_IP_ADDRESS to .csv\n");
        fprintf(stderr, "\t - 'collect_lt' affords to collect !legitimate! traffic metrics for all ips connceted to CLIENT_IP_ADDRESS to .csv\n");
        fprintf(stderr, "\t - 'broadcast' affords to send formated data to educated AI model by WebSocket to detect SS22 in flow by collceted metrics\n");
        return 1;
    }

    client_ip = argv[1];

    // ==============================
    // interruption handler:

    // ==============================

    if(memcmp(argv[3], BROADCAST, strlen(BROADCAST)) == 0) {
        init_websocket();
        mode = BROADCAST;
    } else if (memcmp(argv[3], COLLECT_SS22, strlen(COLLECT_SS22)) == 0) {
        mode = COLLECT_SS22;
    } else if(memcmp(argv[3], COLLECT_LEGITIMATE_TRAFFIC, strlen(COLLECT_LEGITIMATE_TRAFFIC)) == 0) { 
        mode = COLLECT_LEGITIMATE_TRAFFIC;
    } else {
        return 1;
    }

    {
        int *value = malloc(sizeof(int));
        if (value == NULL) { return 1; }

        *value = atoi(argv[2]);
        session_split_delay = value;
    }

    init_flow_stat_array(&ip_stats, 10);
    listen_on_device();
    free_flow_stat_array(&ip_stats);

    return 0;
}