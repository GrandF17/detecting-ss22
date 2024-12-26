#ifndef SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_H_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_H_INCLUDED

#include <stddef.h>

#include "../../constants.h"

void init_ip_port_array(IP_PortArray *array, size_t initial_capacity);
void free_ip_port_array(IP_PortArray *array);
bool contains_ip_port(IP_PortArray *array, uint32_t ip, uint16_t port);
void remove_ip_port(IP_PortArray *array, uint32_t ip, uint16_t port);
int push_back_ip_port(IP_PortArray *array, uint32_t ip, uint16_t port);

#endif