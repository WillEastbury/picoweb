/*
 * Minimal TCP state machine (RFC 9293 §3.3).
 *
 * Spike-grade. Implements the LISTEN -> SYN-RECEIVED -> ESTABLISHED ->
 * CLOSE-WAIT -> LAST-ACK -> CLOSED happy path for a passive open
 * (server). NO retransmit, NO RTO, NO congestion control, NO SACK,
 * NO window-scaling, NO timestamps. We emit one ACK per inbound
 * data segment and ignore zero-window probes. Anything outside the
 * happy path produces a RST.
 *
 * This is enough to satisfy a single curl / openssl-s_client pulling
 * a small body — it WILL eventually melt under any real load.
 *
 * Concrete responsibilities:
 *
 *   - Receive a raw IPv4+TCP segment (already parsed by ip.c).
 *   - Update a connection-control-block.
 *   - Hand decrypted application data up to the TLS record layer
 *     once ESTABLISHED.
 *   - Emit outbound segments via a callback into the AF_PACKET tx.
 *
 * The connection table is intentionally tiny (8 slots) — this is a
 * compile-clean spike, not a production stack.
 */
#ifndef PICOWEB_USERSPACE_TCP_TCP_H
#define PICOWEB_USERSPACE_TCP_TCP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"
#include "../iov.h"
#include "../dispatch.h"

#define TCP_TABLE_SIZE 8u

/* Maximum number of unacked outbound segments tracked per conn for
 * retransmit. Spike-sized; production stacks track many more. The
 * caller MUST keep each segment's payload buffer valid until it is
 * either ACKed or the connection is closed (zero-copy contract). */
#define TCP_RTX_QUEUE_MAX 4u

/* RTO bounds (RFC 6298 §2 + §2.4). RFC mandates RTO_MIN >= 1s for
 * Internet paths; we use 200 ms for the spike so test latency is
 * tolerable. RTO_MAX is the RFC's recommended ceiling. */
#define TCP_RTO_INIT_MS 1000u
#define TCP_RTO_MIN_MS  200u
#define TCP_RTO_MAX_MS  60000u

/* Congestion control (RFC 5681 NewReno + RFC 6928 IW10). MSS is a
 * compile-time constant for the spike (no MSS option negotiation,
 * no PMTU discovery). 1460 = standard Ethernet payload minus
 * 20-byte IPv4 + 20-byte TCP headers. */
#define TCP_MSS              1460u
#define TCP_INIT_CWND        (10u * TCP_MSS)   /* RFC 6928 IW10 */
#define TCP_MIN_CWND         (2u  * TCP_MSS)   /* ssthresh floor */
#define TCP_DUPACK_THRESHOLD 3u                /* fast retransmit trigger */

typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
} tcp_state_t;

/* One unacked segment pending retransmit. Payload pointer must
 * remain valid until the segment is ACKed (zero-copy contract). */
typedef struct {
    uint32_t       seq;          /* first seq of payload                  */
    uint32_t       len;          /* payload length                         */
    const uint8_t* payload;      /* caller-owned, stable until ACK         */
    uint8_t        flags;        /* TCP flags used on original tx          */
    uint8_t        retrans;      /* 1 if at least one retransmit fired     */
    uint64_t       tx_time_ms;   /* when last (re)transmitted              */
} tcp_rtx_entry_t;

typedef struct {
    tcp_state_t state;
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t snd_nxt;       /* next seq to send */
    uint32_t snd_una;       /* oldest unacked seq */
    uint32_t rcv_nxt;       /* next seq we expect to receive */
    uint16_t rcv_wnd;       /* last advertised window (cached for emit) */

    /* Receive-buffer accounting for zero-window flow control.
     * The application increments rcv_buf_used as it accepts bytes
     * into its own buffer (e.g. TLS engine RX), and decrements via
     * tcp_rcv_consumed() as those bytes are drained. The advertised
     * window is rcv_buf_cap - rcv_buf_used, clamped to 65535 (no
     * window scaling in this stack). cap=0 means "use legacy fixed
     * 65535 window" (back-compat default for callers that haven't
     * opted into flow control). */
    uint32_t rcv_buf_cap;
    uint32_t rcv_buf_used;

    /* Retransmit queue + RFC 6298 RTO estimator. All times in ms.
     * srtt_ms == 0 means "no RTT sample taken yet"; first sample
     * sets srtt_ms / rttvar_ms via the RFC initialisation step. */
    tcp_rtx_entry_t rtx[TCP_RTX_QUEUE_MAX];
    uint32_t        rtx_n;
    uint32_t        srtt_ms;
    uint32_t        rttvar_ms;
    uint32_t        rto_ms;

    /* RFC 5681 NewReno congestion control state.
     *   cwnd       - congestion window in bytes (units of TCP_MSS)
     *   ssthresh   - slow-start threshold; UINT32_MAX = "infinite"
     *                until the first loss event
     *   snd_wnd    - peer's advertised receive window (from latest
     *                ACK). Effective send window is min(cwnd, snd_wnd)
     *   dupack_n   - consecutive duplicate ACKs seen for snd_una;
     *                fast retransmit triggers at TCP_DUPACK_THRESHOLD
     *   in_recovery- 1 while in fast-recovery; cleared when snd_una
     *                advances past recovery_seq
     *   recovery_seq - snd_nxt at the moment recovery started; an
     *                ACK >= this exits recovery (NewReno §3.2)
     */
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t snd_wnd;
    uint32_t dupack_n;
    uint32_t recovery_seq;
    uint8_t  in_recovery;

    /* Dispatch-mode plumbing. NULL when the legacy single-port API
     * (tcp_listen + tcp_input(on_data,...)) is in use. */
    const pw_service_t* svc;
    void*               app_state;   /* returned by svc->on_open       */
    uint8_t             opened;      /* on_open fired? on_close pending */
} tcp_conn_t;

typedef struct {
    tcp_conn_t conns[TCP_TABLE_SIZE];
    uint32_t local_ip;

    /* Legacy single-port mode (set by tcp_listen). */
    uint16_t listen_port;

    /* Multi-service dispatch mode (set by tcp_attach_dispatch).
     * If non-NULL, listen_port is ignored and inbound segments are
     * routed by (PW_PROTO_TCP, dst_port) via the dispatch table. */
    const pw_dispatch_t* dispatch;

    /* RFC 6528 ISN secret. Owners SHOULD seed this with 16 bytes
     * of CSPRNG at startup via tcp_stack_set_iss_secret(). If left
     * zero the 4-tuple still produces distinct ISNs but they are
     * predictable to anyone who knows the algorithm — adequate for
     * spike testing, not for production exposure. */
    uint8_t iss_secret[16];
} tcp_stack_t;

/* Application-data callback: called when a fully-acked, in-order
 * payload arrives on an ESTABLISHED connection. (Legacy single-port
 * path only — dispatch services use pw_service_t::on_data instead.) */
typedef void (*tcp_on_data_fn)(tcp_conn_t* c,
                               const uint8_t* data, size_t len,
                               void* user);

/* Emit callback: stack passes the segment back so the I/O layer
 * (AF_PACKET) can prepend the Ethernet header and tx it. */
typedef void (*tcp_emit_fn)(const tcp_seg_t* seg, void* user);

/* One-shot init: bind the stack to a local IP+port. Legacy single-
 * port mode. Returns 0. */
int tcp_listen(tcp_stack_t* s, uint32_t local_ip, uint16_t listen_port);

/* Install a 16-byte secret used to derive RFC 6528 ISNs. SHOULD be
 * called once at startup with bytes from a CSPRNG. Safe to call with
 * any length 0..16; remaining bytes are zero-filled. Without a
 * secret, ISNs are still unique per 4-tuple but predictable. */
void tcp_stack_set_iss_secret(tcp_stack_t* s, const uint8_t* secret, size_t len);

/* Attach a multi-service dispatch table. Replaces the single listen
 * port; inbound segments are routed by (PW_PROTO_TCP, dst_port).
 * The dispatch table MUST outlive the stack and is not modified
 * after this call. Returns 0. */
int tcp_attach_dispatch(tcp_stack_t* s, uint32_t local_ip,
                        const pw_dispatch_t* d);

/* Drive one inbound TCP segment through the state machine.
 *
 * In legacy single-port mode (no dispatch attached) the on_data /
 * on_data_user callback is invoked for in-order app data.
 *
 * In dispatch mode the callback parameters are IGNORED: data is
 * routed via the matched service's on_data. Pass NULLs in that case. */
void tcp_input(tcp_stack_t* s, const tcp_seg_t* seg,
               tcp_on_data_fn on_data, void* on_data_user,
               tcp_emit_fn emit, void* emit_user);

/* Send application data on an ESTABLISHED connection. */
int tcp_send(tcp_conn_t* c,
             const uint8_t* data, size_t len,
             tcp_emit_fn emit, void* emit_user);

/* Scatter-gather variant: emits one segment whose payload is the
 * concatenation of iov[0..n). Total length is computed up front
 * (the "calculate length before TLS is hit" property the user wants).
 * If the total exceeds an MSS the caller should pre-segment, but for
 * the spike we trust callers to keep records under MSS. */
int tcp_sendv(tcp_conn_t* c,
              const pw_iov_t* iov, unsigned n,
              tcp_emit_fn emit, void* emit_user);

/* ------------------------------------------------------------------
 * Receive-buffer flow control (zero-window + persist probe).
 *
 * Set the receive-buffer capacity for a connection. The advertised
 * window in outbound ACKs is clamped to (cap - used). Pass cap=0 to
 * disable flow control (legacy behaviour, fixed 65535 advertised).
 * Typically called from on_open. */
void tcp_set_rcv_buf_cap(tcp_conn_t* c, uint32_t cap);

/* Notify the stack that `n` bytes previously delivered to the
 * application have been drained from its buffer. May open the
 * advertised window from 0 to non-zero; if so, an immediate ACK
 * with the new window is emitted to unstick a peer that has
 * stopped sending. Safe to call with n=0 (no-op). */
void tcp_rcv_consumed(tcp_conn_t* c, uint32_t n,
                      tcp_emit_fn emit, void* emit_user);

/* Compute the window we would advertise right now (cap - used,
 * clamped to 65535; or 65535 if cap == 0). Useful for tests. */
uint16_t tcp_advertised_wnd(const tcp_conn_t* c);

/* ------------------------------------------------------------------
 * Retransmit + RFC 6298 RTO timer.
 *
 * The stack does NOT have its own clock or timer thread. Callers
 * drive the RTO machinery by passing a monotonic millisecond
 * timestamp into tcp_send / tcp_input / tcp_tick. tcp_tick walks
 * all conns and retransmits the oldest unacked segment per conn
 * whose (now - tx_time_ms) >= rto_ms. Karn's algorithm: a
 * retransmitted segment never contributes to the RTT estimator.
 *
 * Bounds: rto_ms is clamped to [TCP_RTO_MIN_MS, TCP_RTO_MAX_MS].
 * Initial RTO is TCP_RTO_INIT_MS until the first RTT sample.
 *
 * The retransmit queue is bounded at TCP_RTX_QUEUE_MAX entries per
 * conn. tcp_send_at returns -1 (queue full) if the cap is hit.
 * Caller-provided payload pointers MUST remain valid until ACKed.
 * ------------------------------------------------------------------ */

/* Time-aware variant of tcp_send. Records the segment in the RTX
 * queue tagged with `now_ms` so RTO + RTT estimator can run. The
 * legacy tcp_send below is equivalent to tcp_send_at(..., now_ms=0)
 * which disables RTX tracking (back-compat). Returns bytes sent or
 * -1 on error / queue full. */
int tcp_send_at(tcp_conn_t* c,
                const uint8_t* data, size_t len,
                uint64_t now_ms,
                tcp_emit_fn emit, void* emit_user);

/* Walk all conns: for each, if there is an unacked segment whose
 * (now_ms - tx_time_ms) >= rto_ms, retransmit it, mark it as
 * retransmitted, double rto_ms (capped at TCP_RTO_MAX_MS), and
 * update tx_time_ms. Time-driven; safe to call frequently. */
void tcp_tick(tcp_stack_t* s, uint64_t now_ms,
              tcp_emit_fn emit, void* emit_user);

/* Time-aware variant of tcp_input. now_ms is used to (a) measure
 * RTT for newly-acked segments (RFC 6298 §3 / Karn's algo) and
 * (b) timestamp the SYN+ACK in the RTX queue. tcp_input is
 * equivalent to tcp_input_at(..., now_ms=0) which still works but
 * never measures RTT. */
void tcp_input_at(tcp_stack_t* s, const tcp_seg_t* seg,
                  uint64_t now_ms,
                  tcp_on_data_fn on_data, void* on_data_user,
                  tcp_emit_fn emit, void* emit_user);

/* ------------------------------------------------------------------
 * Congestion control inspection (read-only helpers; tests + ops).
 *
 * Effective send window is min(cwnd, snd_wnd) - flight_size().
 * Callers that respect this stay within both congestion and flow
 * control bounds. tcp_send_at clamps to this internally.
 * ------------------------------------------------------------------ */
uint32_t tcp_flight_size(const tcp_conn_t* c);
uint32_t tcp_send_window(const tcp_conn_t* c);

#endif
