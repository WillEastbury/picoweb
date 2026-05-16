/*
 * QUIC v1 loss detection (RFC 9002) — phase 4b implementation.
 */
#include "loss.h"

#include <string.h>

/* ---------------- helpers ---------------- */

static uint64_t u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }
static uint64_t u64_min(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t abs_diff(uint64_t a, uint64_t b) { return a > b ? a - b : b - a; }

/* ---------------- RTT (RFC 9002 §5.3) ---------------- */

void quic_rtt_init(quic_rtt_t* r) { memset(r, 0, sizeof(*r)); }

void quic_rtt_sample(quic_rtt_t* r,
                     uint64_t latest_rtt_us,
                     uint64_t ack_delay_us,
                     uint64_t max_ack_delay_us)
{
    r->latest_rtt = latest_rtt_us;

    if (!r->first_sample) {
        r->first_sample  = 1;
        r->min_rtt       = latest_rtt_us;
        r->smoothed_rtt  = latest_rtt_us;
        r->rttvar        = latest_rtt_us / 2;
        return;
    }

    /* min_rtt ignores ack_delay (RFC 9002 §5.2). */
    r->min_rtt = u64_min(r->min_rtt, latest_rtt_us);

    /* Limit ack_delay by max_ack_delay (peer may lie / spec violator). */
    uint64_t delay = ack_delay_us;
    if (max_ack_delay_us > 0 && delay > max_ack_delay_us) delay = max_ack_delay_us;

    /* Apply ack_delay only if doing so keeps adjusted_rtt >= min_rtt. */
    uint64_t adjusted_rtt = latest_rtt_us;
    if (latest_rtt_us >= r->min_rtt + delay) {
        adjusted_rtt = latest_rtt_us - delay;
    }

    /* rttvar = 3/4*rttvar + 1/4*|smoothed_rtt - adjusted_rtt|. */
    uint64_t rttvar_sample = abs_diff(r->smoothed_rtt, adjusted_rtt);
    r->rttvar = (3 * r->rttvar + rttvar_sample) / 4;

    /* smoothed_rtt = 7/8*smoothed_rtt + 1/8*adjusted_rtt. */
    r->smoothed_rtt = (7 * r->smoothed_rtt + adjusted_rtt) / 8;
}

/* ---------------- sent-packet tracker ---------------- */

void quic_loss_init(quic_loss_t* l) { memset(l, 0, sizeof(*l)); }

static quic_sent_pkt_t* find_free(quic_loss_t* l)
{
    for (size_t i = 0; i < QUIC_LOSS_MAX_TRACKED; i++) {
        if (!l->pkts[i].used) return &l->pkts[i];
    }
    return NULL;
}

void quic_loss_on_sent(quic_loss_t* l,
                       uint64_t pn, uint64_t now_us, size_t size,
                       int ack_eliciting, int in_flight)
{
    quic_sent_pkt_t* s = find_free(l);
    if (!s) {
        /* Tracker full — silently drop the oldest. The handshake never
         * needs more than a handful of slots; if we hit this, something
         * is wrong upstream (no ACK processing). */
        size_t oldest = 0;
        for (size_t i = 1; i < QUIC_LOSS_MAX_TRACKED; i++) {
            if (l->pkts[i].time_sent < l->pkts[oldest].time_sent) oldest = i;
        }
        s = &l->pkts[oldest];
    }
    s->pn            = pn;
    s->time_sent     = now_us;
    s->size          = (uint16_t)(size > UINT16_MAX ? UINT16_MAX : size);
    s->ack_eliciting = (uint8_t)(ack_eliciting ? 1 : 0);
    s->in_flight     = (uint8_t)(in_flight ? 1 : 0);
    s->used          = 1;

    if (ack_eliciting) {
        l->time_of_last_ack_eliciting_sent = now_us;
        l->ack_eliciting_in_flight++;
    }
}

static int pn_in_ranges(uint64_t pn,
                        const quic_pn_range_t* ranges, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (pn >= ranges[i].lo && pn <= ranges[i].hi) return 1;
    }
    return 0;
}

static uint64_t loss_delay_us(const quic_rtt_t* rtt)
{
    if (!rtt->first_sample) return QUIC_LOSS_GRANULARITY_US;
    uint64_t base = u64_max(rtt->latest_rtt, rtt->smoothed_rtt);
    uint64_t scaled = base * QUIC_LOSS_TIME_THRESHOLD_NUM
                          / QUIC_LOSS_TIME_THRESHOLD_DEN;
    return u64_max(scaled, QUIC_LOSS_GRANULARITY_US);
}

static size_t detect_lost_inner(quic_loss_t* l,
                                const quic_rtt_t* rtt,
                                uint64_t now_us,
                                uint64_t* out_pns, size_t cap)
{
    l->loss_time = 0;
    if (!l->have_largest_acked) return 0;

    uint64_t delay = loss_delay_us(rtt);
    uint64_t lost_send_time = (now_us > delay) ? (now_us - delay) : 0;

    size_t n = 0;
    for (size_t i = 0; i < QUIC_LOSS_MAX_TRACKED; i++) {
        quic_sent_pkt_t* s = &l->pkts[i];
        if (!s->used) continue;
        if (s->pn > l->largest_acked) continue;
        int by_pn   = (l->largest_acked - s->pn) >= QUIC_LOSS_PACKET_THRESHOLD;
        int by_time = (s->time_sent <= lost_send_time);
        if (by_pn || by_time) {
            if (out_pns && n < cap) out_pns[n] = s->pn;
            n++;
            if (s->ack_eliciting && l->ack_eliciting_in_flight > 0) {
                l->ack_eliciting_in_flight--;
            }
            s->used = 0;
        } else {
            uint64_t deadline = s->time_sent + delay;
            if (l->loss_time == 0 || deadline < l->loss_time) {
                l->loss_time = deadline;
            }
        }
    }
    return n;
}

size_t quic_loss_on_ack(quic_loss_t* l,
                        quic_rtt_t* rtt,
                        const quic_pn_range_t* ranges, size_t n_ranges,
                        uint64_t ack_delay_us,
                        uint64_t max_ack_delay_us,
                        uint64_t now_us,
                        uint64_t* out_lost_pns, size_t out_cap,
                        size_t* out_lost_count)
{
    if (n_ranges == 0) {
        if (out_lost_count) *out_lost_count = 0;
        return 0;
    }

    /* Find largest PN in ranges. */
    uint64_t largest = ranges[0].hi;
    for (size_t i = 1; i < n_ranges; i++) {
        if (ranges[i].hi > largest) largest = ranges[i].hi;
    }
    if (!l->have_largest_acked || largest > l->largest_acked) {
        l->largest_acked = largest;
        l->have_largest_acked = 1;
    }

    /* Sweep tracker: collect newly acked, remember largest-newly-acked. */
    size_t newly_acked = 0;
    int    have_largest_new = 0;
    uint64_t largest_new_pn = 0;
    uint64_t largest_new_send_time = 0;
    int    largest_new_eliciting = 0;

    for (size_t i = 0; i < QUIC_LOSS_MAX_TRACKED; i++) {
        quic_sent_pkt_t* s = &l->pkts[i];
        if (!s->used) continue;
        if (!pn_in_ranges(s->pn, ranges, n_ranges)) continue;
        newly_acked++;
        if (s->ack_eliciting && l->ack_eliciting_in_flight > 0) {
            l->ack_eliciting_in_flight--;
        }
        if (!have_largest_new || s->pn > largest_new_pn) {
            largest_new_pn        = s->pn;
            largest_new_send_time = s->time_sent;
            largest_new_eliciting = s->ack_eliciting;
            have_largest_new      = 1;
        }
        s->used = 0;
    }

    /* RTT sample: only when largest newly-acked is ack-eliciting AND
     * its PN equals the ACK frame's largest acked (RFC 9002 §5.1). */
    if (have_largest_new && largest_new_eliciting && largest_new_pn == largest) {
        uint64_t latest = (now_us > largest_new_send_time)
                          ? (now_us - largest_new_send_time) : 0;
        quic_rtt_sample(rtt, latest, ack_delay_us, max_ack_delay_us);
    }

    /* On any successful ACK reception that newly-acks something,
     * reset PTO back-off (RFC 9002 §6.2.1). */
    if (newly_acked > 0) l->pto_count = 0;

    size_t lost = detect_lost_inner(l, rtt, now_us, out_lost_pns, out_cap);
    if (out_lost_count) *out_lost_count = lost;
    return newly_acked;
}

size_t quic_loss_detect_lost(quic_loss_t* l,
                             const quic_rtt_t* rtt,
                             uint64_t now_us,
                             uint64_t* out_lost_pns, size_t out_cap)
{
    return detect_lost_inner(l, rtt, now_us, out_lost_pns, out_cap);
}

/* ---------------- PTO ---------------- */

uint64_t quic_loss_pto_us(const quic_rtt_t* rtt,
                          uint64_t max_ack_delay_us)
{
    if (!rtt->first_sample) return 0;
    uint64_t v = u64_max(4 * rtt->rttvar, QUIC_LOSS_GRANULARITY_US);
    return rtt->smoothed_rtt + v + max_ack_delay_us;
}

uint64_t quic_loss_pto_deadline(const quic_loss_t* l,
                                const quic_rtt_t* rtt,
                                uint64_t max_ack_delay_us)
{
    if (l->ack_eliciting_in_flight == 0) return 0;
    if (l->time_of_last_ack_eliciting_sent == 0) return 0;
    uint64_t base = quic_loss_pto_us(rtt, max_ack_delay_us);
    if (base == 0) {
        /* No RTT sample yet — RFC 9002 §6.2.2 uses kInitialRtt (333ms). */
        base = 333000 + max_ack_delay_us;
    }
    uint32_t shift = l->pto_count;
    if (shift > 16) shift = 16;
    uint64_t backed = base << shift;
    return l->time_of_last_ack_eliciting_sent + backed;
}
