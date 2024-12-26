#ifndef SNIFFER_LIBS_SRC_DYNAMIC_DOUBLE_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_DOUBLE_C_INCLUDED

#include "../head/dynamic_double.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init_double_array(DoubleArray *array, size_t initial_capacity) {
    array->array = (double *)malloc(initial_capacity * sizeof(double));
    if (array->array == NULL) {
        perror("Failed to allocate memory init_ip_port_array");
        exit(EXIT_FAILURE);
    }
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
        array->capacity = 2 * array->capacity + 1;
        array->array = (double *)realloc(array->array, array->capacity * sizeof(double));
        if (array->array == NULL) {
            perror("Failed to reallocate memory double array");
            exit(EXIT_FAILURE);
        }
    }

    array->array[array->count] = val;
    return (int)array->count++;
}

#endif