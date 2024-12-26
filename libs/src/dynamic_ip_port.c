#ifndef SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_C_INCLUDED

#include <stdio.h>
#include <stdlib.h>

#include "../head/dynamic_ip_port.h"

void init_ip_port_array(IP_PortArray *arr, size_t initial_capacity) {
    arr->size = 0;
    arr->capacity = initial_capacity;
    arr->data = malloc(arr->capacity * sizeof(IP_Port));
    if (!arr->data) {
        perror("Failed to allocate memory init_ip_port_array");
        exit(EXIT_FAILURE);
    }
}

bool contains_ip_port(IP_PortArray *array, uint32_t ip, uint16_t port) {
    for (size_t i = 0; i < array->size; ++i) {
        if (array->data[i].ip == ip && array->data[i].port == port) {
            return true;
        }
    }
    return false;
}

void free_ip_port_array(IP_PortArray *array) {
    free(array->data);
    array->data = NULL;
    array->size = 0;
    array->capacity = 0;
}

int push_back_ip_port(IP_PortArray *array, uint32_t ip, uint16_t port) {
    if (array->size == array->capacity) {
        array->capacity = 2 * array->capacity + 1;
        array->data = (IP_Port *)realloc(array->data, array->capacity * sizeof(IP_Port));
        if (!array->data) {
            perror("Failed to reallocate memory ip_port array");
            exit(EXIT_FAILURE);
        }
    }
    array->data[array->size].ip = ip;
    array->data[array->size].port = port;
    return (int)array->size++;
}

void remove_ip_port(IP_PortArray *array, uint32_t ip, uint16_t port) {
    for (size_t i = 0; i < array->size; ++i) {
        if (array->data[i].ip == ip && array->data[i].port == port) {
            array->data[i] = array->data[--array->size];
            return;
        }
    }
}

#endif