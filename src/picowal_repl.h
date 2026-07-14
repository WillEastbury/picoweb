#ifndef METAL_PICOWAL_REPL_H
#define METAL_PICOWAL_REPL_H

/* Primary-side segment-aware physical replication feed for picowal: exposes
 * base.dat + WAL segments so a replica can mirror them and serve reads
 * locally (multi-reader / single-writer topology, e.g. for load balancing
 * read traffic across nodes behind an LB while all writes go to one
 * primary). See picowal_db.h for the on-disk base.dat/WAL-segment model
 * this mirrors.
 *
 *   GET {prefix}status              -> JSON {"leading_wal_id":N,
 *                                        "leading_write_off":N,
 *                                        "segment_bytes":N,"next_seq":N}
 *   GET {prefix}segments            -> JSON {"segments":[
 *                                        {"seg_id":N,"generation":N,
 *                                         "sealed":bool,"bytes":N}, ...]}
 *   GET {prefix}segment/{id}/{gen}  -> whole-file bytes of base.dat
 *                                        (id=0) or a SEALED WAL segment,
 *                                        at the given generation.
 *                                        Content-Type: application/octet-stream
 *                                        410 Gone if generation is stale
 *                                        (caller should re-list segments).
 *   GET {prefix}stream/{id}/{off}   -> raw bytes [off, min(off+chunk,
 *                                        write_off)) of the CURRENT
 *                                        leading WAL segment only. 409
 *                                        Conflict if {id} just got sealed
 *                                        by rotation (fetch it wholesale
 *                                        via /segment/{id}/{gen} instead
 *                                        and start following the new
 *                                        leading id from offset 0).
 *   POST {prefix}ack/{id}/{off}     -> replica reports "I've durably
 *                                        applied up through {off} of
 *                                        leading WAL segment {id}"; the
 *                                        request body (a short ASCII id,
 *                                        <=63 bytes) identifies the
 *                                        replica, defaulting to "replica"
 *                                        if the body is empty.
 *                                        Feeds PICOWAL_DURABILITY_REPLICATED
 *                                        quorum waits. 204 No Content.
 *
 * ({id}/{off}/{gen} are path segments, not query parameters -- http_parse()
 * strips any "?..." query string before routing ever sees the request
 * path.)
 *
 * A replica reconciles by: GET segments, wholesale-fetch (or drop) any
 * base.dat/sealed-segment whose (seg_id,generation) it doesn't already
 * have locally via /segment/{id}/{gen} + picowal_db_repl_install_segment(),
 * drop any local segment id no longer listed via
 * picowal_db_repl_drop_segment(), then incrementally follow the current
 * leading id via /stream/{id}/{off} + picowal_db_repl_ingest_segment().
 * A primary checkpoint only ever costs a replica one base.dat re-fetch
 * plus dropping now-removed WAL segment ids -- it never disturbs a
 * replica that's already caught up on the actively-growing leading
 * segment.
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
                           const char* body, size_t body_len,
                           const char* write_token, size_t write_token_len,
                           api_resp_t* resp);

#endif
