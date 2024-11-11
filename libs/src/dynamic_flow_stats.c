#ifndef SNIFFER_LIBS_SRC_DYNAMIC_FLOW_STATS_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_FLOW_STATS_C_INCLUDED

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../head/dynamic_flow_stats.h"
#include "../head/dynamic_size_t.h"
#include "../head/dynamic_double.h"

void init_flow_stat_array(FlowStatArray *array, size_t initial_capacity) {
    array->array = (FlowStat *)malloc(initial_capacity * sizeof(FlowStat));
    array->count = 0;
    array->capacity = initial_capacity;
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
        printf("create_stat start (old)\n");
        // free mem space
        free_double_array(&array->array[ip_id].packet_entropy);
        free_size_t_array(&array->array[ip_id].packet_sizes);
        memset(&array->array[ip_id], 0, sizeof(FlowStat));

        // allocate new mem space
        strcpy(array->array[ip_id].rec_ip, ip_address);
        init_double_array(&array->array[ip_id].packet_entropy, 10);
        init_size_t_array(&array->array[ip_id].packet_sizes, 10);

        printf("create_stat end (old)\n");
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

    printf("create_stat start (new)\n");

    strcpy(array->array[array->count].rec_ip, ip_address);
    init_double_array(&array->array[array->count].packet_entropy, 10);
    init_size_t_array(&array->array[array->count].packet_sizes, 10);
    
    printf("create_stat end (new)\n");
    return (int)array->count++;
}

#endif