#ifndef SNIFFER_MODULES_ENTROPY_C_INCLUDED
#define SNIFFER_MODULES_ENTROPY_C_INCLUDED

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * according to chineese specialists,
 * GFW blocks traffic wich contains [3.4, 4.6] '1' per 8 bits
 * that equals to 0.98370826 of packet entropy
 *
 * entropy calculation shows best effect on data more than 256 bytes
 */
static double SS22_ENTROPY = 0.98370826;
static const uint8_t bit_count_table[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

// for packet
static double count_packet_entropy(const uint8_t *data, uint16_t len) {
    size_t filled_bits = 0;
    for (uint16_t i = 0; i < len; ++i) {
        filled_bits += bit_count_table[data[i]];
    }

    size_t total_bits = len * 8;
    size_t empty_bits = total_bits - filled_bits;

    if (filled_bits == 0 || empty_bits == 0) return 0.0;

    double empty_probability = (double)empty_bits / total_bits;
    double filled_probability = (double)filled_bits / total_bits;
    double entropy = -empty_probability * log2(empty_probability) - filled_probability * log2(filled_probability);

    return entropy;
}

// for amounts of '0' and '1'
static double count_bin_entropy(const size_t empty_bits, const size_t filled_bits) {
    size_t total_bits = empty_bits + filled_bits;

    if (empty_bits == 0 || filled_bits == 0) return 0.0;

    double empty_probability = (double)empty_bits / total_bits;
    double filled_probability = (double)filled_bits / total_bits;
    double entropy = -empty_probability * log2(empty_probability) - filled_probability * log2(filled_probability);

    return entropy;
}

#endif