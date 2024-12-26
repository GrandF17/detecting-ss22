#ifndef SNIFFER_LIBS_SRC_DYNAMIC_SIZE_T_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_SIZE_T_C_INCLUDED

#include "../head/dynamic_size_t.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init_size_t_array(SizeTArray *array, size_t initial_capacity) {
    array->array = (size_t *)malloc(initial_capacity * sizeof(size_t));
    if (array->array == NULL) {
        perror("Failed to allocate memory init_ip_port_array");
        exit(EXIT_FAILURE);
    }
    array->count = 0;
    array->capacity = initial_capacity;
}

void free_size_t_array(SizeTArray *array) {
    free(array->array);
    array->array = NULL;
    array->count = 0;
    array->capacity = 0;
}

int push_back_size_t(SizeTArray *array, size_t val) {
    if (array->count >= array->capacity) {
        array->capacity = 2 * array->capacity + 1;
        array->array = (size_t *)realloc(array->array, array->capacity * sizeof(size_t));
        if (array->array == NULL) {
            perror("Failed to reallocate memory size_t array");
            exit(EXIT_FAILURE);
        }
    }

    array->array[array->count] = val;
    return (int)array->count++;
}

#endif