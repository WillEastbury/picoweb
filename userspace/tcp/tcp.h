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

typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
} tcp_state_t;

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

#endif
