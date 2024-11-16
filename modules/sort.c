#ifndef SNIFFER_MODULES_SORT_C_INCLUDED
#define SNIFFER_MODULES_SORT_C_INCLUDED

#include <stddef.h>
#include <stdlib.h>

int compare_double(const void *a, const void *b) {
    double diff = (*(double *)a - *(double *)b);
    return (diff > 0) - (diff < 0);
}

int compare_size_t(const void *a, const void *b) {
    size_t val_a = *(size_t *)a;
    size_t val_b = *(size_t *)b;
    return (val_a > val_b) - (val_a < val_b);
}

#define sort(arr, n) \
    _Generic((arr), \
        double*: qsort(arr, n, sizeof(double), compare_double), \
        size_t*: qsort(arr, n, sizeof(size_t), compare_size_t) \
    )

#endif