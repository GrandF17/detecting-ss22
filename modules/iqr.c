#ifndef SNIFFER_MODULES_IQR_C_INCLUDED
#define SNIFFER_MODULES_IQR_C_INCLUDED

#include "../constants.h"

#include "./sort.c"

QuartileResultSizeT IQR_size_t(size_t *arr, size_t tags_amount) {
    sort(arr, tags_amount);
    
    size_t Q1_idx = tags_amount / 4;
    size_t Q3_idx = 3 * tags_amount / 4;

    double Q1 = arr[Q1_idx];
    double Q3 = arr[Q3_idx];

    double Q2;
    if (tags_amount % 2 == 0) {
        Q2 = (arr[(tags_amount / 2) - 1] + arr[tags_amount / 2]) / 2.0;
    } else {
        Q2 = arr[tags_amount / 2];
    }

    QuartileResultSizeT result = {Q1, Q2, Q3, Q3 - Q1};
    return result;
}

QuartileResultDouble IQR_double(double *arr, size_t tags_amount) {
    sort(arr, tags_amount);

    size_t Q1_idx = tags_amount / 4;
    size_t Q3_idx = 3 * tags_amount / 4;

    double Q1 = arr[Q1_idx];
    double Q3 = arr[Q3_idx];

    // Рассчитываем Q2 (медиана)
    double Q2;
    if (tags_amount % 2 == 0) {
        Q2 = (arr[(tags_amount / 2) - 1] + arr[tags_amount / 2]) / 2.0;
    } else {
        Q2 = arr[tags_amount / 2];
    }

    QuartileResultDouble result = {Q1, Q2, Q3, Q3 - Q1};
    return result;
}

#define IQR(arr, tags_amount) \
    _Generic((arr), \
        size_t*: IQR_size_t, \
        double*: IQR_double \
    )(arr, tags_amount)

#endif