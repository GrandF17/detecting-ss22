#ifndef SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_H_INCLUDED
#define SNIFFER_LIBS_SRC_DYNAMIC_IP_PORT_H_INCLUDED

#include <stddef.h>

#include "../../constants.h"

void push_back_ip_port(IP_PortArray *arr, uint32_t ip, uint16_t port);
bool contains_ip_port(IP_PortArray *arr, uint32_t ip, uint16_t port);
void remove_ip_port(IP_PortArray *arr, uint32_t ip, uint16_t port);
void free_ip_port(IP_PortArray *arr);

#endif