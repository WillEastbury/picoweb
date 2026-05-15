/*
 * QUIC v1 NewReno congestion control (RFC 9002 §7) — phase 4c.
 */
#include "cc.h"
#include <string.h>

static uint64_t u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }
static uint64_t u64_min(uint64_t a, uint64_t b) { return a < b ? a : b; }

uint64_t quic_cc_initial_window(uint64_t mds)
{
    /* RFC 9002 §B kInitialWindow = min(10*MDS, max(2*MDS, 14720)). */
    return u64_min(10 * mds, u64_max(2 * mds, 14720));
}

uint64_t quic_cc_minimum_window(uint64_t mds)
{
    return 2 * mds;
}

void quic_cc_init(quic_cc_t* cc, uint64_t mds)
{
    memset(cc, 0, sizeof(*cc));
    cc->max_datagram_size = mds;
    cc->cwnd              = quic_cc_initial_window(mds);
    cc->ssthresh          = UINT64_MAX;
    cc->ssthresh_set      = 0;
}

void quic_cc_on_sent(quic_cc_t* cc, uint64_t bytes)
{
    cc->bytes_in_flight += bytes;
}

void quic_cc_on_acked(quic_cc_t* cc, uint64_t bytes)
{
    if (bytes > cc->bytes_in_flight) bytes = cc->bytes_in_flight;
    cc->bytes_in_flight -= bytes;

    if (cc->cwnd < cc->ssthresh) {
        /* Slow start: cwnd += bytes. */
        cc->cwnd += bytes;
    } else {
        /* Congestion avoidance: cwnd += MDS * bytes / cwnd. */
        cc->cwnd += (cc->max_datagram_size * bytes) / cc->cwnd;
    }
}

void quic_cc_on_lost(quic_cc_t* cc, uint64_t bytes,
                     uint64_t lost_send_time, uint64_t now_us)
{
    if (bytes > cc->bytes_in_flight) bytes = cc->bytes_in_flight;
    cc->bytes_in_flight -= bytes;

    /* Recovery period: react at most once per RTT (§7.3.2). A new loss
     * only collapses cwnd if its send time is after the current
     * recovery period started. */
    if (cc->congestion_recovery_start_time != 0 &&
        lost_send_time <= cc->congestion_recovery_start_time) {
        return;
    }
    cc->congestion_recovery_start_time = now_us;

    /* ssthresh = cwnd / 2, then cwnd = max(ssthresh, kMinimumWindow). */
    uint64_t halved = cc->cwnd / 2;
    uint64_t min_w  = quic_cc_minimum_window(cc->max_datagram_size);
    cc->ssthresh    = u64_max(halved, min_w);
    cc->ssthresh_set = 1;
    cc->cwnd        = cc->ssthresh;
}

void quic_cc_on_persistent_congestion(quic_cc_t* cc)
{
    cc->cwnd = quic_cc_minimum_window(cc->max_datagram_size);
    cc->congestion_recovery_start_time = 0;
}

int quic_cc_can_send(const quic_cc_t* cc, uint64_t bytes)
{
    return cc->bytes_in_flight + bytes <= cc->cwnd;
}
