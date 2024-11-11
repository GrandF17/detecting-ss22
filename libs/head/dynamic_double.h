#ifndef SNIFFER_LIBS_SRC_DYNAMIC_DOUBLE_H_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_DOUBLE_H_INCLUDED

#include <stddef.h>

#include "../../constants.h"

int init_double_array(DoubleArray *array, size_t initial_capacity);
void free_double_array(DoubleArray *array);
int push_back_double(DoubleArray *array, double val);

#endif