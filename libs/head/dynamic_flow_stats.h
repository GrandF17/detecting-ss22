#ifndef SNIFFER_LIBS_SRC_DYNAMIC_FLOW_STATS_H_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_FLOW_STATS_H_INCLUDED

#include <stddef.h>

#include "../../constants.h"

int init_flow_stat_array(FlowStatArray *array, size_t initial_capacity);
void free_flow_stat_array(FlowStatArray *array);
int get_stat_idx(FlowStatArray *array, const char *ip_address, const uint16_t port);
int create_stat(FlowStatArray *array, const char *ip_address, const uint16_t port);

#endif