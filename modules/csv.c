#ifndef SNIFFER_MODULES_CSV_C_INCLUDED
#define SNIFFER_MODULES_CSV_C_INCLUDED

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "./constants.h"

int appendCSV(const char* file_name, const FlowStat* data) {
    FILE* file = fopen(file_name, "a");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    fprintf(file, "%ld, ", data->min_packet_size);
    fprintf(file, "%ld, ", data->max_packet_size);
    fprintf(file, "%.4f, ", data->packet_len_deviation);
    fprintf(file, "%.4f, ", data->entropy);
    fprintf(file, "%.4f, ", data->entropy_deviation);
    fprintf(file, "%d, ", (uint8_t)data->udp_lable);
    fprintf(file, "%d, ", (uint8_t)data->tcp_lable);
    fprintf(file, "%d, ", (uint8_t)data->sctp_lable);
    fprintf(file, "%d, ", (uint8_t)data->tls_lable);
    fprintf(file, "%d, ", (uint8_t)data->ssh_lable);
    fprintf(file, "1\n");  // 1 --> ss22, 0 --> other

    fclose(file);
    return 0;
}

void logCSV(const FlowStat* data) {
    printf("%ld, ", data->min_packet_size);
    printf("%ld, ", data->max_packet_size);
    printf("%.4f, ", data->packet_len_deviation);
    printf("%.4f, ", data->entropy);
    printf("%.4f, ", data->entropy_deviation);
    printf("%d, ", (uint8_t)data->udp_lable);
    printf("%d, ", (uint8_t)data->tcp_lable);
    printf("%d, ", (uint8_t)data->sctp_lable);
    printf("%d, ", (uint8_t)data->tls_lable);
    printf("%d, ", (uint8_t)data->ssh_lable);
    printf("1\n");  // 1 --> ss22, 0 --> other
}

#endif