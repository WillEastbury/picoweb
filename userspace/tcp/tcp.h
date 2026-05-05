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
    uint16_t rcv_wnd;       /* advertised window */
} tcp_conn_t;

typedef struct {
    tcp_conn_t conns[TCP_TABLE_SIZE];
    uint32_t local_ip;
    uint16_t listen_port;
} tcp_stack_t;

/* Application-data callback: called when a fully-acked, in-order
 * payload arrives on an ESTABLISHED connection. */
typedef void (*tcp_on_data_fn)(tcp_conn_t* c,
                               const uint8_t* data, size_t len,
                               void* user);

/* Emit callback: stack passes the segment back so the I/O layer
 * (AF_PACKET) can prepend the Ethernet header and tx it. */
typedef void (*tcp_emit_fn)(const tcp_seg_t* seg, void* user);

/* One-shot init: bind the stack to a local IP+port. Returns 0. */
int tcp_listen(tcp_stack_t* s, uint32_t local_ip, uint16_t listen_port);

/* Drive one inbound TCP segment through the state machine. */
void tcp_input(tcp_stack_t* s, const tcp_seg_t* seg,
               tcp_on_data_fn on_data, void* on_data_user,
               tcp_emit_fn emit, void* emit_user);

/* Send application data on an ESTABLISHED connection. */
int tcp_send(tcp_conn_t* c,
             const uint8_t* data, size_t len,
             tcp_emit_fn emit, void* emit_user);

#endif
