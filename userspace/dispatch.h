/*
 * Pre-jump table for L4 services (RFC 9293 TCP, RFC 768 UDP).
 *
 * The picoweb userspace stack is multipurpose: a single TCP/UDP stack
 * can host many independent services (HTTPS on 443, HTTP on 80, gossip
 * on 7777, DNS on 53, ...). The dispatch table is a small, packed,
 * cache-line-friendly array of (proto, port) -> service callbacks
 * built once at startup and never mutated again.
 *
 * Why a packed linear scan and not a hash table:
 *   - N is small (<= PW_DISPATCH_MAX = 16). The whole array fits in a
 *     single cache line, the comparison is a u16 == u16, and the
 *     branch predictor wins easily for small N. A hash with a separate
 *     bucket array would touch more cache and pay an extra indirection
 *     for nothing.
 *   - "Built once at startup" matches the project's no-allocation-
 *     after-startup invariant.
 *
 * Lifecycle contract (TCP):
 *
 *   on_open  : called EXACTLY ONCE per connection, AFTER the TCP
 *              handshake reaches ESTABLISHED. This is deliberate -
 *              if we called it on SYN, half-open connections would
 *              consume scarce per-conn state and SYN-flood us out
 *              of the pool. on_open returns a per-conn state pointer
 *              (typically rented from a fixed-size pool the service
 *              owns), or NULL to refuse the connection (TCP layer
 *              will RST).
 *
 *   on_data  : called for each in-order data chunk. The service
 *              writes outbound bytes by populating iov_out[0..iov_max)
 *              with (ptr, len) descriptors pointing at long-lived
 *              storage owned by the service. Sets *iov_n. Returns
 *              a pw_disp_status_t describing what the TCP layer
 *              should do (send + close? reset? nothing?).
 *
 *   on_close : called EXACTLY ONCE for every successful on_open
 *              (FIN, RST, app-initiated close, or stack teardown).
 *              NEVER called if on_open returned NULL. The service
 *              uses this to release its per-conn state back to the
 *              pool.
 *
 * Lifecycle contract (UDP, when udp.c lands):
 *
 *   on_data  : called once per inbound datagram. per_conn_state is
 *              the service's svc_state pointer (UDP is connectionless,
 *              there is no per-flow open/close).
 *   on_open  : ignored.
 *   on_close : ignored.
 *
 * The dispatch table itself is IMMUTABLE after attach (i.e. after
 * tcp_attach_dispatch / udp_attach_dispatch). Stored pointers stay
 * valid for the lifetime of the stack.
 */

#ifndef PICOWEB_USERSPACE_DISPATCH_H
#define PICOWEB_USERSPACE_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#include "iov.h"

#define PW_DISPATCH_MAX 16

typedef enum {
    PW_PROTO_TCP = 6,
    PW_PROTO_UDP = 17,
} pw_proto_t;

/* Read-only metadata view passed to services. We deliberately do NOT
 * hand a tcp_conn_t* to services - that would couple them to TCP
 * internals and let them violate transport invariants. */
typedef struct {
    uint32_t   remote_ip;
    uint16_t   remote_port;
    uint32_t   local_ip;
    uint16_t   local_port;
    pw_proto_t proto;
} pw_conn_info_t;

/* What the TCP layer should do after a service callback returns. */
typedef enum {
    PW_DISP_NO_OUTPUT        = 0,  /* don't send anything (just ACK)        */
    PW_DISP_OUTPUT           = 1,  /* sendv iov_out[0..iov_n)               */
    PW_DISP_OUTPUT_AND_CLOSE = 2,  /* sendv then send FIN                   */
    PW_DISP_RESET            = 3,  /* RST the connection                    */
    PW_DISP_ERROR            = 4,  /* internal error - treat as reset       */
} pw_disp_status_t;

/* Connection lifecycle hooks. */
typedef void* (*pw_on_open_fn)(void* svc_state, const pw_conn_info_t* info);
typedef pw_disp_status_t (*pw_on_data_fn)(void* per_conn_state,
                                          const uint8_t* data, size_t len,
                                          pw_iov_t* iov_out, unsigned iov_max,
                                          unsigned* iov_n);
typedef void (*pw_on_close_fn)(void* per_conn_state);

typedef struct {
    pw_proto_t      proto;
    uint16_t        port;
    void*           svc_state;
    pw_on_open_fn   on_open;     /* may be NULL for stateless services */
    pw_on_data_fn   on_data;     /* MUST be set                         */
    pw_on_close_fn  on_close;    /* may be NULL for stateless services */
} pw_service_t;

typedef struct {
    pw_service_t entries[PW_DISPATCH_MAX];
    unsigned     n;
} pw_dispatch_t;

/* Initialise an empty dispatch table. Idempotent. */
void pw_dispatch_init(pw_dispatch_t* d);

/* Register a service. Returns 0 on success, -1 on:
 *   - duplicate (proto, port)
 *   - table full
 *   - svc->on_data == NULL
 *   - svc->port == 0
 */
int  pw_dispatch_register(pw_dispatch_t* d, const pw_service_t* svc);

/* Lookup the service for a (proto, port) tuple.
 * Returns the matching entry pointer or NULL. The returned pointer is
 * stable for the lifetime of the dispatch table. */
const pw_service_t* pw_dispatch_lookup(const pw_dispatch_t* d,
                                       pw_proto_t proto, uint16_t port);

#endif
