#ifndef SNIFFER_MODULES_RANGE_COUNTER_C_INCLUDED
#define SNIFFER_MODULES_RANGE_COUNTER_C_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

bool check_first_six_bytes(const uint8_t *data, uint16_t len) {
    if (len < 6) return false;
    for (int i = 0; i < 6; i++) {
        if (data[i] < 0x20 || data[i] > 0x7e) {
            return false; // bytes are in range: [0x20, 0x7e]
        }
    }
    return true;
}

bool check_more_than_50_percent(const uint8_t *data, uint16_t len) {
    int count = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7e) {
            count++;
        }
    }
    return count > (len / 2);
}

bool check_more_than_20_contiguous(const uint8_t *data, uint16_t len) {
    int contiguous_count = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7e) {
            contiguous_count++;
            if (contiguous_count > 20) {
                return true; // more than 20 in a row
            }
        } else {
            contiguous_count = 0; // reset counter
        }
    }
    return false;
}

#endif