/*
 * QUIC v1 flow control (RFC 9000 §4) — phase 4c.
 *
 * Two layers, each with send-side and recv-side credit:
 *   1. Connection-level: max_data (bytes of STREAM payload across
 *      all streams).
 *   2. Per-stream: max_stream_data (bytes per stream).
 *
 * This module is a pure accountant — caller decides when to emit
 * MAX_DATA / MAX_STREAM_DATA frames based on quic_flow_should_update().
 */
#ifndef PICOWEB_USERSPACE_QUIC_FLOW_H
#define PICOWEB_USERSPACE_QUIC_FLOW_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t max;            /* peer's advertised limit */
    uint64_t consumed;       /* bytes we have written/read */
} quic_flow_t;

/* Initialize with peer's initial limit. */
void quic_flow_init(quic_flow_t* f, uint64_t initial_max);

/* Try to consume `bytes` of credit. Returns bytes actually granted,
 * which may be less than requested (or 0) if the window is full. */
uint64_t quic_flow_consume(quic_flow_t* f, uint64_t bytes);

/* Bytes available right now. */
uint64_t quic_flow_available(const quic_flow_t* f);

/* Increase the limit (e.g. on receipt of MAX_DATA). Per RFC 9000
 * §19.9 the limit only ever increases; smaller values are ignored. */
void quic_flow_set_max(quic_flow_t* f, uint64_t new_max);

/* Receive-side helper: returns nonzero when we should send a
 * MAX_DATA / MAX_STREAM_DATA update. Heuristic: when consumed crosses
 * `max - window/2`, push the limit forward. */
int quic_flow_should_update(const quic_flow_t* f, uint64_t initial_window);

#endif
