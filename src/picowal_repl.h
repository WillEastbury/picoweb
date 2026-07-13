#ifndef METAL_PICOWAL_REPL_H
#define METAL_PICOWAL_REPL_H

/* Primary-side physical replication feed for picowal: exposes the raw,
 * append-only log as a byte stream so a replica can mirror it and serve
 * reads locally (multi-reader / single-writer topology, e.g. for load
 * balancing read traffic across nodes behind an LB while all writes go
 * to one primary).
 *
 *   GET {prefix}status         -> JSON {"write_off":N,"volume_bytes":N,
 *                                        "next_seq":N,"sector_size":512}
 *   GET {prefix}stream/N       -> raw bytes [N, min(N+chunk, write_off))
 *                                  Content-Type: application/octet-stream
 *                                  X-Picowal-From, X-Picowal-Write-Off,
 *                                  X-Picowal-Chunk-Len response headers
 *
 * (N is a path segment, not a query parameter -- http_parse() strips any
 * "?..." query string before routing ever sees the request path, so an
 * offset passed as "?from=N" would never reach this handler.)
 *
 * `from` must be sector-aligned (512) and >= PICOWAL_DATA_START (1024;
 * the two-slot A/B superblock region is never streamed -- a replica
 * formats its own volume on first sync). A replica appends the returned
 * bytes verbatim to its own copy of the file at the same offset and calls
 * picowal_db_repl_ingest() to replay them into its local index.
 *
 * Always gated by api_require_write_token() (a shared secret configured
 * via --picowal-write-token / PICOWAL_WRITE_TOKEN) -- this is a distinct,
 * machine-to-machine trust boundary from browser session cookies, and
 * streams the entire raw (unvalidated-by-schema) log, so it refuses to
 * serve at all (503) if no token is configured, same posture as the
 * static-pack/pico-route raw write routes. */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "http.h"
#include "api.h"

bool picowal_repl_enabled(void);

/* Configure once on the main thread, after api_picowal_init() has opened
 * the volume. prefix must start and end with '/'. */
bool picowal_repl_init(const char* prefix);

bool picowal_repl_path_matches(const char* path, size_t path_len);

void picowal_repl_dispatch(http_method_t method,
                           const char* path, size_t path_len,
                           const char* write_token, size_t write_token_len,
                           api_resp_t* resp);

#endif
