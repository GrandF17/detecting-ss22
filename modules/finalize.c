#ifndef SNIFFER_MODULES_FINALIZE_C_INCLUDED
#define SNIFFER_MODULES_FINALIZE_C_INCLUDED

#include "../constants.h"
#include "./deviation.c"
#include "./entropy.c"
#include "./iqr.c"
#include "./csv.c"

/**
 * counting parameters:
 * - deviation
 * - timestamps
 */
void finalize_flow(FlowStat *session) {
    session->std_pckt_size = deviation(session->packet_sizes.array, session->packet_sizes.count);
    session->std_entropy = deviation(session->packet_entropy.array, session->packet_entropy.count);
    session->entropy = count_bin_entropy(session->empty_bits, session->filled_bits);

    // math statistics
    QuartileResultSizeT pckt_sizes_IQR = IQR(session->packet_sizes.array, session->packet_sizes.count);
    session->q1_pckt_size = pckt_sizes_IQR.Q1;
    session->q2_pckt_size = pckt_sizes_IQR.Q2;
    session->q3_pckt_size = pckt_sizes_IQR.Q3;
    session->iqr_pckt_size = pckt_sizes_IQR.IQR;

    // outliners:
    double lower_bound_pct_sizes = pckt_sizes_IQR.Q1 - 1.5 * pckt_sizes_IQR.IQR;
    double upper_bound_pct_sizes = pckt_sizes_IQR.Q1 + 1.5 * pckt_sizes_IQR.IQR;

    for (int i = 0; i < session->packet_sizes.count; ++i) {
        if (session->packet_sizes.array[i] < lower_bound_pct_sizes) {
            ++session->pckt_size_outliers_lb;
        }
        if (session->packet_sizes.array[i] > upper_bound_pct_sizes) {
            ++session->pckt_size_outliers_lb;
        }
    }

    QuartileResultDouble entropy_IQR = IQR(session->packet_entropy.array, session->packet_entropy.count);
    session->q1_entropy = entropy_IQR.Q1;
    session->q2_entropy = entropy_IQR.Q2;
    session->q3_entropy = entropy_IQR.Q3;
    session->iqr_entropy = entropy_IQR.IQR;

    // outliners:
    double lower_bound_entropy = entropy_IQR.Q1 - 1.5 * entropy_IQR.IQR;
    double upper_bound_entropy = entropy_IQR.Q3 + 1.5 * entropy_IQR.IQR;

    for (int i = 0; i < session->packet_entropy.count; ++i) {
        if (session->packet_entropy.array[i] < lower_bound_entropy) {
            ++session->entropy_outliers_lb;
        }
        if (session->packet_entropy.array[i] > upper_bound_entropy) {
            ++session->entropy_outliers_ub;
        }
    }

    // time
    session->total_time = session->last_upd - session->start;
    session->avg_waiting_time = session->total_time / (double)session->packet_sizes.count;

    appendCSV("data.csv", session);
    logCSV(session);
}

#endif