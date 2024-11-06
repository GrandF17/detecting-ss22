#ifndef SNIFFER_MODULES_DEVIATION_C_INCLUDED
#define SNIFFER_MODULES_DEVIATION_C_INCLUDED

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

double count_deviation(size_t* array_of_tags, size_t tags_amount) {
    size_t sum = 0;
    for (size_t i = 0; i < tags_amount; ++i) {
        sum += array_of_tags[i];
    }

    double mean = (double)sum / tags_amount;
    double variance_sum = 0.0;

    for (size_t i = 0; i < tags_amount; i++) {
        variance_sum += (array_of_tags[i] - mean) * (array_of_tags[i] - mean);
    }

    return sqrt(variance_sum / tags_amount);
}

double count_deviation_double(double* array_of_tags, size_t tags_amount) {
    double sum = 0.0;
    for (size_t i = 0; i < tags_amount; ++i) {
        sum += array_of_tags[i];
    }

    double mean = sum / tags_amount;
    double variance_sum = 0.0;

    for (size_t i = 0; i < tags_amount; i++) {
        variance_sum += (array_of_tags[i] - mean) * (array_of_tags[i] - mean);
    }

    return sqrt(variance_sum / tags_amount);
}

#define count_deviation_generic(arr, tags_amount) \
    _Generic((arr), \
        size_t*: count_deviation, \
        double*: count_deviation_double \
    )(arr, tags_amount)

#endif