#ifndef SNIFFER_MODULES_CSV_C_INCLUDED
#define SNIFFER_MODULES_CSV_C_INCLUDED

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int appendCSV(const char* file_name,
              const size_t name_len,
              const uint32_t* data,
              const size_t data_len) {
    FILE* file = fopen(file_name, "a");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    for (size_t i = 0; i < data_len; ++i) {
        fprintf(file, "%d", data[i]);
        if (i == data_len - 1) {
            fprintf(file, "\n");
        } else {
            fprintf(file, ",");
        }
    }

    fclose(file);
    return 0;
}

#endif