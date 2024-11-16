#ifndef SNIFFER_MODULES_MEDIAN_C_INCLUDED
#define SNIFFER_MODULES_MEDIAN_C_INCLUDED

#include "./sort.c"

double median_double(double* array_of_tags, size_t tags_amount) {
    sort(array_of_tags, tags_amount);
    
    if(tags_amount % 2 == 0) {
        return (array_of_tags[tags_amount / 2 - 1] + array_of_tags[tags_amount / 2 + 1]) / 2;
    } else {
        return array_of_tags[tags_amount / 2];
    }
}

double median_size_t(size_t* array_of_tags, size_t tags_amount)  {
    sort(array_of_tags, tags_amount);
    
    if(tags_amount % 2 == 0) {
        return (array_of_tags[tags_amount / 2 - 1] + array_of_tags[tags_amount / 2 + 1]) / 2;
    } else {
        return array_of_tags[tags_amount / 2];
    }
}

#define median(arr, n) \
    _Generic((arr), \
        double*: median_double(arr, n), \
        size_t*: median_size_t(arr, n) \
    )

#endif