#ifndef SNIFFER_LIBS_SRC_DYNAMIC_DOUBLE_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_DOUBLE_C_INCLUDED

#include <stdlib.h>
#include <string.h>

#include "../head/dynamic_double.h"

void init_double_array(DoubleArray *array, size_t initial_capacity) {
    array->array = (double *)malloc(initial_capacity * sizeof(double));
    array->count = 0;
    array->capacity = initial_capacity;
}

void free_double_array(DoubleArray *array) {
    free(array->array);
    array->array = NULL;
    array->count = 0;
    array->capacity = 0;
}

int push_back_double(DoubleArray *array, double val) {
    if (array->count >= array->capacity) {
        size_t new_capacity = array->capacity * 2;
        double *new_array = (double *)realloc(array->array, new_capacity * sizeof(double));
        if (new_array == NULL) {
            return -1;
        }
        array->array = new_array;
        array->capacity = new_capacity;
    }

    array->array[array->count] = val;
    return (int)array->count++;
}

#endif