#ifndef SNIFFER_LIBS_HEAD_DYNAMIC_SIZE_T_H_INCLUDED
#define SNIFFER_LIBS_HEAD_DYNAMIC_SIZE_T_H_INCLUDED

#include <stddef.h>

#include "../../constants.h"

int init_size_t_array(SizeTArray *array, size_t initial_capacity);
void free_size_t_array(SizeTArray *array);
int push_back_size_t(SizeTArray *array, size_t val);

#endif