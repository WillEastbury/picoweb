/*
 * QUIC v1 loss detection (RFC 9002) — phase 4b.
 *
 * RTT estimator + sent-packet tracker + packet/time-threshold loss
 * detection + PTO timer computation. Pure state — no I/O, no clock.
 * Caller supplies monotonic microsecond timestamps so the module is
 * trivial to unit-test.
 *
 * Per-packet-number-space: instantiate one tracker per Initial /
 * Handshake / Application key epoch.
 */
#ifndef PICOWEB_USERSPACE_QUIC_LOSS_H
#define PICOWEB_USERSPACE_QUIC_LOSS_H

#include <stdint.h>
#include <stddef.h>

/* RFC 9002 §A.2 constants. */
#define QUIC_LOSS_PACKET_THRESHOLD     3
#define QUIC_LOSS_GRANULARITY_US       1000      /* 1 ms */
#define QUIC_LOSS_TIME_THRESHOLD_NUM   9         /* 9/8 multiplier */
#define QUIC_LOSS_TIME_THRESHOLD_DEN   8

#define QUIC_LOSS_MAX_TRACKED          256

typedef struct {
    uint64_t latest_rtt;
    uint64_t smoothed_rtt;
    uint64_t rttvar;
    uint64_t min_rtt;
    int      first_sample;   /* 0 until first sample taken */
} quic_rtt_t;

typedef struct {
    uint64_t pn;
    uint64_t time_sent;      /* microseconds */
    uint16_t size;           /* on-wire bytes (for CC accounting later) */
    uint8_t  ack_eliciting;
    uint8_t  in_flight;
    uint8_t  used;           /* 0 = slot empty */
    uint8_t  _pad;
} quic_sent_pkt_t;

typedef struct {
    quic_sent_pkt_t pkts[QUIC_LOSS_MAX_TRACKED];
    uint64_t largest_acked;
    int      have_largest_acked;
    uint64_t loss_time;                       /* 0 = no pending loss timer */
    uint64_t time_of_last_ack_eliciting_sent; /* monotonic; never reset */
    uint32_t pto_count;
    uint32_t ack_eliciting_in_flight;         /* live count for PTO arming */
} quic_loss_t;

typedef struct {
    uint64_t lo;             /* inclusive */
    uint64_t hi;             /* inclusive */
} quic_pn_range_t;

/* ---------------- RTT ---------------- */

void quic_rtt_init(quic_rtt_t* r);

/* Apply one RTT sample per RFC 9002 §5.3. ack_delay is the receiver-
 * reported value (already scaled). max_ack_delay caps it after the
 * handshake confirms — pass 0 during the handshake. */
void quic_rtt_sample(quic_rtt_t* r,
                     uint64_t latest_rtt_us,
                     uint64_t ack_delay_us,
                     uint64_t max_ack_delay_us);

/* ---------------- sent-packet tracker ---------------- */

void quic_loss_init(quic_loss_t* l);

/* Record a sent packet. ack_eliciting=1 if the packet contains any
 * ACK-eliciting frame (CRYPTO, STREAM, PING, etc — but not pure ACK
 * or PADDING). in_flight=1 if it consumes congestion window. */
void quic_loss_on_sent(quic_loss_t* l,
                       uint64_t pn, uint64_t now_us, size_t size,
                       int ack_eliciting, int in_flight);

/* Process an incoming ACK. Updates largest_acked, removes acked
 * packets, and (if the largest newly-acked PN is ack-eliciting)
 * derives an RTT sample and feeds it to *rtt.
 *
 * Returns the number of newly-acked packets. Optional outputs:
 *  - out_lost_pns / out_cap: receives PNs detected as lost.
 *  - returns count in *out_lost_count. */
size_t quic_loss_on_ack(quic_loss_t* l,
                        quic_rtt_t* rtt,
                        const quic_pn_range_t* ranges, size_t n_ranges,
                        uint64_t ack_delay_us,
                        uint64_t max_ack_delay_us,
                        uint64_t now_us,
                        uint64_t* out_lost_pns, size_t out_cap,
                        size_t* out_lost_count);

/* Re-run loss detection without an ACK (e.g. on loss-timer fire).
 * Same semantics as the lost-packet sweep inside quic_loss_on_ack.
 * Returns number of newly-detected lost packets. */
size_t quic_loss_detect_lost(quic_loss_t* l,
                             const quic_rtt_t* rtt,
                             uint64_t now_us,
                             uint64_t* out_lost_pns, size_t out_cap);

/* Probe Timeout (RFC 9002 §6.2.1) in microseconds, NOT including
 * pto_count back-off. Returns 0 if no RTT sample yet (use initial RTT
 * elsewhere). */
uint64_t quic_loss_pto_us(const quic_rtt_t* rtt,
                          uint64_t max_ack_delay_us);

/* Absolute deadline at which the PTO timer should fire, or 0 if
 * no ack-eliciting packet is in flight. Includes 2^pto_count back-off. */
uint64_t quic_loss_pto_deadline(const quic_loss_t* l,
                                const quic_rtt_t* rtt,
                                uint64_t max_ack_delay_us);

#endif
