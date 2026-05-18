/*
 * QUIC v1 NewReno congestion control (RFC 9002 §7) — phase 4c.
 *
 * Pure state. No timers. Caller supplies microsecond timestamps so the
 * recovery-period check is deterministic.
 *
 * RFC 9002 §B constants:
 *   kInitialWindow   = min(10*MDS, max(2*MDS, 14720))
 *   kMinimumWindow   = 2*MDS
 *   kLossReduction   = 0.5
 *   kPersistentCongestionThreshold = 3
 */
#ifndef PICOWEB_USERSPACE_QUIC_CC_H
#define PICOWEB_USERSPACE_QUIC_CC_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_CC_DEFAULT_MDS  1200   /* worst-case Initial-flight MTU */

typedef struct {
    uint64_t max_datagram_size;
    uint64_t cwnd;
    uint64_t ssthresh;
    uint64_t bytes_in_flight;
    uint64_t congestion_recovery_start_time;  /* 0 = not in recovery */
    int      ssthresh_set;                    /* 0 ⇒ slow start */
} quic_cc_t;

void quic_cc_init(quic_cc_t* cc, uint64_t max_datagram_size);

uint64_t quic_cc_initial_window(uint64_t max_datagram_size);
uint64_t quic_cc_minimum_window(uint64_t max_datagram_size);

/* On packet sent — only call for in_flight packets. */
void quic_cc_on_sent(quic_cc_t* cc, uint64_t bytes);

/* On packets acked — call once per acked in-flight packet. now_us is
 * used only by quic_cc_on_lost to avoid double-reaction. */
void quic_cc_on_acked(quic_cc_t* cc, uint64_t bytes);

/* On packets lost. now_us is the loss-detection time. lost_send_time
 * is the time the lost packet was sent (used for recovery-period
 * check: only enter recovery if lost_send_time > recovery_start). */
void quic_cc_on_lost(quic_cc_t* cc, uint64_t bytes,
                     uint64_t lost_send_time, uint64_t now_us);

/* On persistent congestion (no ACK in window > persistent_congestion_duration).
 * Collapses cwnd to kMinimumWindow. */
void quic_cc_on_persistent_congestion(quic_cc_t* cc);

/* Can send another packet of `bytes` size right now? */
int quic_cc_can_send(const quic_cc_t* cc, uint64_t bytes);

#endif
