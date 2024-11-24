#ifndef SNIFFER_MODULES_BUFFER_C_INCLUDED
#define SNIFFER_MODULES_BUFFER_C_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../constants.h"

size_t format_session(char *buffer, size_t buffer_size, FlowStat *session) {
    // recording metric headers
    int header_length = snprintf(buffer, buffer_size, "%s", CSV_BROADCAST);
    if (header_length < 0 || (size_t)header_length >= buffer_size) {
        fprintf(stderr, "Error: buffer overflow while writing headers.\n");
        return 0;
    }

    // recording flow metrics
    int value_length = snprintf(
        buffer + header_length, 
        buffer_size - header_length,
        "%.6f,%d,%d,%d,%d,%.6f,%.6f,%ld,%ld,%ld,%ld,%ld,%ld,%.6f,%.6f,%.6f,%.6f,%.6f,%ld,%ld,%d,%d,%d,%d,%d,%d,%llu,%llu,%ld,%ld,%ld,%ld,%ld",
        session->first_pct_stat.entropy,
        (int)(session->first_pct_stat.range_of_six),
        (int)(session->first_pct_stat.range_of_half),
        (int)(session->first_pct_stat.range_seq),
        (int)(session->first_pct_stat.is_http_or_tls),
        session->entropy,
        session->std_pckt_size,
        session->q1_pckt_size,
        session->q2_pckt_size,
        session->q3_pckt_size,
        session->iqr_pckt_size,
        session->pckt_size_outliers_lb,
        session->pckt_size_outliers_ub,
        session->std_entropy,
        session->q1_entropy,
        session->q2_entropy,
        session->q3_entropy,
        session->iqr_entropy,
        session->entropy_outliers_lb,
        session->entropy_outliers_ub,
        (int)(session->udp_lable),
        (int)(session->tcp_lable),
        (int)(session->sctp_lable),
        (int)(session->http_lable),
        (int)(session->tls_lable),
        (int)(session->ssh_lable),
        session->total_time,
        session->avg_waiting_time,
        session->client_pckt_amount,
        session->server_pckt_amount,
        session->min_pckt_size,
        session->max_pckt_size,
        session->keep_alive_pckt_amount
    );

    // recording ip addr:
    int ip_len = snprintf(
        buffer + header_length + value_length, 
        buffer_size - header_length - value_length,
        "\n%s",
        session->rec_ip
    );
     

    if(value_length < 0 || (size_t)(header_length + value_length + ip_len) >= buffer_size) {
        fprintf(stderr, "Error: buffer overflow while writing values.\n");
        return 0;
    }

    return header_length + value_length + ip_len;
}

#endif