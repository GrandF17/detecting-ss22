#ifndef SNIFFER_MODULES_CSV_C_INCLUDED
#define SNIFFER_MODULES_CSV_C_INCLUDED

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../constants.h"

int appendCSV(const char* file_name, const FlowStat* data) {
    FILE* file = fopen(file_name, "a");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    fprintf(file, "%.6f, ", data->first_pct_stat.entropy);
    fprintf(file, "%d, ", (uint8_t)data->first_pct_stat.correct_range_six);
    fprintf(file, "%d, ", (uint8_t)data->first_pct_stat.correct_range_half);
    fprintf(file, "%d, ", (uint8_t)data->first_pct_stat.correct_range_sequence);
    fprintf(file, "%d, ", (uint8_t)data->first_pct_stat.is_http_or_tls);

    fprintf(file, "%.6f, ", data->total_time);
    fprintf(file, "%.6f, ", data->average_waiting_time);
    fprintf(file, "%ld, ", data->client_pckt_amount);
    fprintf(file, "%ld, ", data->server_pckt_amount);
    fprintf(file, "%ld, ", data->min_packet_size);
    fprintf(file, "%ld, ", data->max_packet_size);
    fprintf(file, "%.6f, ", data->packet_size_deviation);
    fprintf(file, "%.6f, ", data->entropy);
    fprintf(file, "%.6f, ", data->entropy_deviation);

    // lables:
    fprintf(file, "%d, ", (uint8_t)data->udp_lable);
    fprintf(file, "%d, ", (uint8_t)data->tcp_lable);
    fprintf(file, "%d, ", (uint8_t)data->sctp_lable);
    fprintf(file, "%d, ", (uint8_t)data->http_lable);
    fprintf(file, "%d, ", (uint8_t)data->tls_lable);
    fprintf(file, "%d, ", (uint8_t)data->ssh_lable);
    fprintf(file, "0\n");  // 1 --> ss22, 0 --> other

    fclose(file);
    return 0;
}

void logCSV(const FlowStat* data) {
    printf("%s, ", data->rec_ip);

    // first packet:
    printf("%.6f, ", data->first_pct_stat.entropy);
    printf("%d, ", (uint8_t)data->first_pct_stat.correct_range_six);
    printf("%d, ", (uint8_t)data->first_pct_stat.correct_range_half);
    printf("%d, ", (uint8_t)data->first_pct_stat.correct_range_sequence);
    printf("%d, ", (uint8_t)data->first_pct_stat.is_http_or_tls);

    printf("%.6f, ", data->average_waiting_time);
    printf("%ld, ", data->client_pckt_amount);
    printf("%ld, ", data->server_pckt_amount);
    printf("%ld, ", data->min_packet_size);
    printf("%ld, ", data->max_packet_size);
    printf("%.6f, ", data->packet_size_deviation);
    printf("%.6f, ", data->entropy);
    printf("%.6f, ", data->entropy_deviation);

    // lables:
    printf("%d, ", (uint8_t)data->udp_lable);
    printf("%d, ", (uint8_t)data->tcp_lable);
    printf("%d, ", (uint8_t)data->sctp_lable);
    printf("%d, ", (uint8_t)data->http_lable);
    printf("%d, ", (uint8_t)data->tls_lable);
    printf("%d, ", (uint8_t)data->ssh_lable);
    printf("0\n");  // 1 --> ss22, 0 --> other
}

#endif