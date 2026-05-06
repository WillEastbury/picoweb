#ifndef METAL_POOL_H
#define METAL_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "jumptable.h"

#define METAL_READ_BUF 8192

typedef enum {
    ST_READING = 0,
    ST_WRITING = 1
} conn_state_t;

typedef struct conn {
    struct conn* next_free;     /* free-list link when idle */
    int          fd;            /* -1 when free */
    conn_state_t state;

    /* Read side */
    size_t   read_off;          /* bytes valid in read_buf */

    /* Write side — pointers into immutable arena memory, no copies. */
    const resource_t* res;
    const char*       head_ptr;
    size_t            head_len;
    bool              send_body;
    const resource_compress_t* active_variant; /* non-NULL = serving compressed body */
    size_t            bytes_sent;     /* 0..head_len + (send_body ? body_len : 0) */
    bool              close_after;

    /* Per-connection lifetime caps & flags */
    uint32_t req_count;          /* # full requests served on this conn */
    bool     peer_half_closed;   /* peer sent FIN; close after current resp */

    /* Latency timing for /stats. Set in dispatch_one after a successful
     * parse; consumed in post_send when the response is fully sent.
     * 0 means "no in-flight request to record". TSC ticks
     * (rdtsc / cntvct_el0). */
    uint64_t req_start_tsc;

    /* Bookkeeping. last_active_ms is refreshed ONLY at request/response
     * boundaries (NOT on every byte) so a slow drip-feeder cannot keep
     * the connection alive past idle_ms. */
    int64_t  last_active_ms;

    /* Inline read buffer — the only writable runtime memory on the
     * request path. */
    char     read_buf[METAL_READ_BUF];
} conn_t;

/* A per-worker pool of connection slots, mmapped at startup. */
typedef struct {
    conn_t*  base;
    size_t   cap;
    conn_t*  free_head;
    size_t   in_use;
} pool_t;

bool   pool_init(pool_t* p, size_t cap);
conn_t* pool_alloc(pool_t* p);
void   pool_free(pool_t* p, conn_t* c);

#endif
