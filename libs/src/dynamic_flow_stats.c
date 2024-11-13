#ifndef SNIFFER_LIBS_SRC_DYNAMIC_FLOW_STATS_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_FLOW_STATS_C_INCLUDED

#include "../head/dynamic_flow_stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../head/dynamic_double.h"
#include "../head/dynamic_size_t.h"

int init_flow_stat_array(FlowStatArray *array, size_t initial_capacity) {
    array->array = (FlowStat *)malloc(initial_capacity * sizeof(FlowStat));
    if (array->array == NULL) {
        return -1;
    }
    array->count = 0;
    array->capacity = initial_capacity;
    return 0;
}

void free_flow_stat_array(FlowStatArray *array) {
    free(array->array);
    array->array = NULL;
    array->count = 0;
    array->capacity = 0;
}

int get_stat_idx(FlowStatArray *array, const char *ip_address) {
    for (size_t i = 0; i < array->count; ++i) {
        if (strcmp(array->array[i].rec_ip, ip_address) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int create_stat(FlowStatArray *array, const char *ip_address) {
    int ip_id = get_stat_idx(array, ip_address);
    if (ip_id != -1) {
        // free mem space
        free_double_array(&array->array[ip_id].packet_entropy);
        free_size_t_array(&array->array[ip_id].packet_sizes);

        // instead of 'memset(&array->array[ip_id], 0, sizeof(FlowStat));'

        // first pct stats:
        array->array[ip_id].first_pct_stat.entropy = 0.0;
        array->array[ip_id].first_pct_stat.is_http_or_tls = false;
        array->array[ip_id].first_pct_stat.correct_range_six = false;
        array->array[ip_id].first_pct_stat.correct_range_half = false;
        array->array[ip_id].first_pct_stat.correct_range_sequence = false;

        // other metrics:
        array->array[ip_id].average_waiting_time = 0;
        array->array[ip_id].total_time = 0;
        array->array[ip_id].client_pckt_amount = 0;
        array->array[ip_id].server_pckt_amount = 0;
        array->array[ip_id].min_packet_size = 0;
        array->array[ip_id].max_packet_size = 0;
        array->array[ip_id].packet_size_deviation = 0;
        array->array[ip_id].entropy = 0;
        array->array[ip_id].entropy_deviation = 0;

        // time metrics:
        array->array[ip_id].start = 0;
        array->array[ip_id].last_upd = 0;

        // lables:
        array->array[ip_id].udp_lable = false;
        array->array[ip_id].tcp_lable = false;
        array->array[ip_id].sctp_lable = false;
        array->array[ip_id].http_lable = false;
        array->array[ip_id].tls_lable = false;
        array->array[ip_id].ssh_lable = false;

        // srevice metrics:
        array->array[ip_id].empty_bits = 0;
        array->array[ip_id].filled_bits = 0;

        // allocate new mem space
        // strcpy(array->array[ip_id].rec_ip, ip_address);
        init_double_array(&array->array[ip_id].packet_entropy, 10);
        init_size_t_array(&array->array[ip_id].packet_sizes, 10);

        return ip_id;
    }

    if (array->count >= array->capacity) {
        size_t new_capacity = array->capacity * 2;
        FlowStat *new_array = (FlowStat *)realloc(array->array, new_capacity * sizeof(FlowStat));
        if (new_array == NULL) {
            return -1;
        }
        array->array = new_array;
        array->capacity = new_capacity;
    }

    strcpy(array->array[array->count].rec_ip, ip_address);
    init_double_array(&array->array[array->count].packet_entropy, 10);
    init_size_t_array(&array->array[array->count].packet_sizes, 10);

    return (int)array->count++;
}

#endif