#ifndef SNIFFER_MODULES_CSV_C_INCLUDED
#define SNIFFER_MODULES_CSV_C_INCLUDED

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../constants.h"

int is_file_empty_or_nonexistent(const char *filename) {
    FILE *file = fopen(filename,"r");
    if (!file) return 1;

    int ch = fgetc(file);
    fclose(file);

    return ch == EOF;
}


int appendCSV(const char* file_name, const FlowStat* data) {
    FILE* file = fopen(file_name,"a");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    if(is_file_empty_or_nonexistent(file_name)) {
        fprintf(file, CSV_HEAD);
    }

    // first packet:
    fprintf(file,"%.6f,", data->first_pct_stat.entropy);
    fprintf(file,"%d,", (uint8_t)(data->first_pct_stat.range_of_six));
    fprintf(file,"%d,", (uint8_t)(data->first_pct_stat.range_of_half));
    fprintf(file,"%d,", (uint8_t)(data->first_pct_stat.range_seq));
    fprintf(file,"%d,", (uint8_t)(data->first_pct_stat.is_http_or_tls));

    fprintf(file,"%.6f,", data->entropy);

    fprintf(file,"%.6f,", data->std_pckt_size);
    fprintf(file,"%ld,", data->q1_pckt_size);
    fprintf(file,"%ld,", data->q2_pckt_size);
    fprintf(file,"%ld,", data->q3_pckt_size);
    fprintf(file,"%ld,", data->iqr_pckt_size);
    fprintf(file,"%ld,", data->pckt_size_outliers_lb);
    fprintf(file,"%ld,", data->pckt_size_outliers_ub);

    fprintf(file,"%.6f,", data->std_entropy);
    fprintf(file,"%.6f,", data->q1_entropy);
    fprintf(file,"%.6f,", data->q2_entropy);
    fprintf(file,"%.6f,", data->q3_entropy);
    fprintf(file,"%.6f,", data->iqr_entropy);
    fprintf(file,"%ld,", data->entropy_outliers_lb);
    fprintf(file,"%ld,", data->entropy_outliers_ub);

    // lables:
    fprintf(file,"%d,", (uint8_t)(data->udp_lable));
    fprintf(file,"%d,", (uint8_t)(data->tcp_lable));
    fprintf(file,"%d,", (uint8_t)(data->sctp_lable));
    fprintf(file,"%d,", (uint8_t)(data->http_lable));
    fprintf(file,"%d,", (uint8_t)(data->tls_lable));
    fprintf(file,"%d,", (uint8_t)(data->ssh_lable));

    fprintf(file,"%llu,", data->total_time);
    fprintf(file,"%llu,", data->avg_waiting_time);
    fprintf(file,"%ld,", data->client_pckt_amount);
    fprintf(file,"%ld,", data->server_pckt_amount);
    fprintf(file,"%ld,", data->min_pckt_size);
    fprintf(file,"%ld,", data->max_pckt_size);
    fprintf(file,"%ld,", data->keep_alive_pckt_amount);

    /* here you can INSERT your own metrics to write down to the file */

    // ...

    /* here you can INSERT your own metrics to write down to the file */

    fprintf(file,"0\n");  // 1 --> ss22, 0 --> other

    fclose(file);
    return 0;
}

void logCSV(const FlowStat* data) {
    printf("IP %s: ", data->rec_ip);

    // first packet:
    printf("%.6f,", data->first_pct_stat.entropy);
    printf("%d,", (uint8_t)(data->first_pct_stat.range_of_six));
    printf("%d,", (uint8_t)(data->first_pct_stat.range_of_half));
    printf("%d,", (uint8_t)(data->first_pct_stat.range_seq));
    printf("%d,", (uint8_t)(data->first_pct_stat.is_http_or_tls));

    printf("%.6f,", data->entropy);
    
    printf("%.6f,", data->std_pckt_size);
    printf("%ld,", data->q1_pckt_size);
    printf("%ld,", data->q2_pckt_size);
    printf("%ld,", data->q3_pckt_size);
    printf("%ld,", data->iqr_pckt_size);
    printf("%ld,", data->pckt_size_outliers_lb);
    printf("%ld,", data->pckt_size_outliers_ub);

    printf("%.6f,", data->std_entropy);
    printf("%.6f,", data->q1_entropy);
    printf("%.6f,", data->q2_entropy);
    printf("%.6f,", data->q3_entropy);
    printf("%.6f,", data->iqr_entropy);
    printf("%ld,", data->entropy_outliers_lb);
    printf("%ld,", data->entropy_outliers_ub);

    // lables:
    printf("%d,", (uint8_t)(data->udp_lable));
    printf("%d,", (uint8_t)(data->tcp_lable));
    printf("%d,", (uint8_t)(data->sctp_lable));
    printf("%d,", (uint8_t)(data->http_lable));
    printf("%d,", (uint8_t)(data->tls_lable));
    printf("%d,", (uint8_t)(data->ssh_lable));

    printf("%llu,", data->total_time);
    printf("%llu,", data->avg_waiting_time);
    printf("%ld,", data->client_pckt_amount);
    printf("%ld,", data->server_pckt_amount);
    printf("%ld,", data->min_pckt_size);
    printf("%ld,", data->max_pckt_size);
    printf("%ld,", data->keep_alive_pckt_amount);

    /* here you can INSERT your own metrics to log in console */

    // ...

    /* here you can INSERT your own metrics to log in console */

    printf("0\n");  // 1 --> ss22, 0 --> other
}

#endif