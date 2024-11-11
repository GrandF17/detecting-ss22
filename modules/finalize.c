#ifndef SNIFFER_MODULES_FINALIZE_C_INCLUDED
#define SNIFFER_MODULES_FINALIZE_C_INCLUDED

#include "../constants.h"
#include "./deviation.c"
#include "./entropy.c"
#include "./csv.c"

/**
 * counting parameters:
 * - deviation
 * - timestamps
 */
void finalize_flow(FlowStat *session) {
    session->packet_size_deviation = count_deviation_generic(session->packet_sizes.array, session->packet_sizes.count);
    session->entropy_deviation = count_deviation_generic(session->packet_entropy.array, session->packet_entropy.count);
    session->entropy = count_bin_entropy(session->empty_bits, session->filled_bits);
    
    session->total_time = session->last_upd - session->start;
    session->average_waiting_time = session->total_time / (double)session->packet_sizes.count;

    appendCSV("data.csv", session);
    logCSV(session);
}

#endif