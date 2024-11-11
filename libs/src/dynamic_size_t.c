#ifndef SNIFFER_LIBS_SRC_DYNAMIC_SIZE_T_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_SIZE_T_C_INCLUDED

#include <stdlib.h>
#include <string.h>

#include "../head/dynamic_size_t.h"

void init_size_t_array(SizeTArray *array, size_t initial_capacity) {
    array->array = (size_t *)malloc(initial_capacity * sizeof(size_t));
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
        size_t new_capacity = array->capacity * 2;
        size_t *new_array = (size_t *)realloc(array->array, new_capacity * sizeof(size_t));
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