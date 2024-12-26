#ifndef SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_C_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_C_INCLUDED

#include <stdlib.h>
#include <stdio.h>

#include "../head/dynamic_ip_port.h"

void push_back_ip_port(IP_PortArray *arr, uint32_t ip, uint16_t port) {
    if (arr->size == arr->capacity) {
        arr->capacity *= 2;
        arr->data = realloc(arr->data, arr->capacity * sizeof(IP_Port));
        if (!arr->data) {
            printf("Failed to reallocate memory");
            exit(EXIT_FAILURE);
        }
    }
    arr->data[arr->size].ip = ip;
    arr->data[arr->size].port = port;
    arr->size++;
}

bool contains_ip_port(IP_PortArray *arr, uint32_t ip, uint16_t port) {
    for (size_t i = 0; i < arr->size; i++) {
        if (arr->data[i].ip == ip && arr->data[i].port == port) {
            return true;
        }
    }
    return false;
}

void remove_ip_port(IP_PortArray *arr, uint32_t ip, uint16_t port) {
    for (size_t i = 0; i < arr->size; i++) {
        if (arr->data[i].ip == ip && arr->data[i].port == port) {
            for (size_t j = i; j < arr->size - 1; j++) {
                arr->data[j] = arr->data[j + 1];
            }
            arr->size--;
            return;
        }
    }
}

void free_ip_port(IP_PortArray *arr) {
    free(arr->data);
    arr->data = NULL;
    arr->size = 0;
    arr->capacity = 0;
}

#endif