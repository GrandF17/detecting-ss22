#ifndef SNIFFER_MODULES_DEVIATION_C_INCLUDED
#define SNIFFER_MODULES_DEVIATION_C_INCLUDED

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

double count_deviation(size_t* packet_sizes, size_t packets_amount) {
    size_t sum = 0;
    for (size_t i = 0; i < packets_amount; ++i) {
        sum += packet_sizes[i];
    }

    double mean = (double)sum / packets_amount;
    double variance_sum = 0.0;

    for (size_t i = 0; i < packets_amount; i++) {
        variance_sum += (packet_sizes[i] - mean) * (packet_sizes[i] - mean);
    }

    return sqrt(variance_sum / packets_amount);
}

#endif