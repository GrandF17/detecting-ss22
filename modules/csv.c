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

    fprintf(file, "%d, ", data->min_packet_size);
    fprintf(file, "%d, ", data->max_packet_size);
    fprintf(file, "%d, ", data->packet_len_deviation);
    fprintf(file, "%d, ", data->entropy);
    fprintf(file, "%d, ", data->entropy_deviation);
    fprintf(file, "%d, ", (uint8_t)data->udp_lable);
    fprintf(file, "%d, ", (uint8_t)data->tcp_lable);
    fprintf(file, "%d, ", (uint8_t)data->sctp_lable);
    fprintf(file, "%d, ", (uint8_t)data->tls_lable);
    fprintf(file, "%d, ", (uint8_t)data->ssh_lable);
    fprintf(file, "1\n");  // 1 --> ss22, 0 --> other

    fclose(file);
    return 0;
}

void log(const FlowStat* data) {
    printf("%d, ", data->min_packet_size);
    printf("%d, ", data->max_packet_size);
    printf("%d, ", data->packet_len_deviation);
    printf("%d, ", data->entropy);
    printf("%d, ", data->entropy_deviation);
    printf("%d, ", (uint8_t)data->udp_lable);
    printf("%d, ", (uint8_t)data->tcp_lable);
    printf("%d, ", (uint8_t)data->sctp_lable);
    printf("%d, ", (uint8_t)data->tls_lable);
    printf("%d, ", (uint8_t)data->ssh_lable);
    printf("1\n");  // 1 --> ss22, 0 --> other
}

#endif