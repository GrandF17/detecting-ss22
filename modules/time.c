#ifndef SNIFFER_MODULES_TIME_C_INCLUDED
#define SNIFFER_MODULES_TIME_C_INCLUDED

#include <time.h>

long long milliseconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    // micros' to millis'
    return now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
}

#endif