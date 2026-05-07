#ifndef METAL_JUMPTABLE_H
#define METAL_JUMPTABLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "arena.h"

/* A per-host header/footer "chrome" pair. Bytes live in the immutable
 * arena. Shared across every HTML resource for the host, so the
 * memory cost is per-host, not per-resource. */
typedef struct {
    const char* hdr;     size_t hdr_len;
    const char* ftr;     size_t ftr_len;
} __attribute__((aligned(64))) chrome_t;

/* A pre-built compressed variant of a resource. The wire payload is
 * the FULL response body (chrome.hdr || body || chrome.ftr if chromed,
 * else just body) compressed once at startup. When this variant is
 * served the iovec collapses to two segments — head_pc + body_pc —
 * because chrome bytes are baked into the compressed stream.
 *
 * Lives in the immutable arena. Built only for compressible MIME
 * types (text slash any, application/json, application/javascript,
 * application/xml, image/svg+xml) and only kept if it actually
 * shrinks the payload. */
typedef struct {
    const char* head_keepalive;  size_t head_keepalive_len;
    const char* head_close;      size_t head_close_len;
    const char* body;            size_t body_len;     /* compressed bytes */
} __attribute__((aligned(64))) resource_compress_t;

/* A pre-built HTTP response: head (status + headers, ending in \r\n\r\n)
 * in two flavours, plus an optional body and optional chrome.
 *
 * For a chrome'd HTML page the wire payload is three contiguous
 * segments: chrome->hdr || body || chrome->ftr. Total length
 * (= what Content-Length: in the head bakes in) is precomputed at
 * build time. The hot path sendmsg's an iovec of up to 4 entries
 * (head + hdr + body + ftr) — pointers, no copies, no formatting.
 *
 * For non-HTML or no-chrome resources, chrome == NULL and the iovec
 * collapses to the original 2 entries (head + body).
 *
 * The optional `compressed` pointer references a precomputed
 * `resource_compress_t` for clients that send Accept-Encoding:
 * picoweb-compress (or BareMetal.Compress legacy alias). NULL if
 * compression wasn't worth it (e.g. binary payload, or compressed
 * size exceeded original). One pointer = 8 bytes, fits in the
 * existing tail padding so resource_t stays at exactly 64 bytes.
 *
 * All pointers reference either immutable arena memory or, for the
 * /stats endpoint specifically, a fixed-length writable region that
 * the metrics updater rewrites in place. Aligned to 64B so the hot
 * fields share a single cache line. */
typedef struct {
    const char* head_keepalive;  size_t head_keepalive_len;
    const char* head_close;      size_t head_close_len;
    const char* body;            size_t body_len;
    const chrome_t* chrome;      /* NULL if no chrome is applied */
    const resource_compress_t* compressed; /* NULL if no compressed variant */
    const resource_compress_t* brotli;     /* NULL if no Brotli variant */
    /* Conditional GET: weak ETag computed at startup from body hash.
     * etag points into arena (e.g. W/"0a1b2c3d4e5f6789").
     * head_304_* are prebuilt 304 Not Modified response heads.
     * NULL for dynamic resources (/stats, /health) and errors. */
    const char* etag;            size_t etag_len;
    const char* head_304_keepalive; size_t head_304_keepalive_len;
    const char* head_304_close;     size_t head_304_close_len;
} __attribute__((aligned(128))) resource_t;

/* One flat-table slot. value == NULL marks the slot empty.
 * Layout is exactly one cache line so each probe touches a single
 * line and slots never straddle. host_len + path_len are packed into
 * one uint32 (`lens`) so equality is a single 4-byte compare. */
typedef struct {
    uint64_t     hash;            /* FNV-1a of lower(host)|path */
    resource_t*  value;           /* NULL = empty */
    const char*  host;            /* lowercased, into arena */
    const char*  path;            /* into arena, leading '/' */
    uint32_t     lens;            /* (host_len << 16) | path_len */
    uint32_t     _pad32;
    char         _cacheline_pad[24];
} __attribute__((aligned(64))) flat_slot_t;

typedef struct {
    arena_t      arena;
    flat_slot_t* slots;        /* in arena */
    size_t       cap;          /* power of two */
    size_t       mask;         /* cap - 1 */
    size_t       size;
    bool         has_default;  /* true if "_default" host has any entries */

    /* Canned error responses (both head variants present so caller
     * picks based on framing safety). */
    const resource_t* err_400;
    const resource_t* err_404;
    const resource_t* err_405;
    const resource_t* err_413;
    const resource_t* err_414;
    const resource_t* err_505;
} jumptable_t;

/* Build the jump table by scanning wwwroot/<host>/...
 * Each immediate child directory of wwwroot is a host name. The
 * special name "_default" is the fallback host. */
bool jumptable_build(jumptable_t* jt, const char* wwwroot);

/* Lookup: returns NULL on miss. host/path are NOT NUL-terminated and
 * MUST already be normalised by the parser (host lowercased + port
 * stripped; path leading-slash + safe). */
const resource_t* jumptable_lookup(const jumptable_t* jt,
                                   const char* host, size_t host_len,
                                   const char* path, size_t path_len);

#endif
