#ifndef METAL_PICOWAL_REPL_CLIENT_H
#define METAL_PICOWAL_REPL_CLIENT_H

/* Replica-side puller for picowal_repl.c's primary replication feed.
 * Spawns a background thread that repeatedly polls a primary's
 * {prefix}status / {prefix}stream endpoints over plain HTTP (no TLS --
 * run this over a private/trusted network, e.g. a VPC or WireGuard mesh,
 * or in front of a TLS-terminating sidecar) and applies received log
 * bytes to the local picowal volume via picowal_db_repl_ingest(), turning
 * this node into a read replica: local /wal/ mutation routes should be
 * refused (see picowal_replica_mode_enabled()) while GET/HEAD reads keep
 * serving out of the continuously-updated local copy -- multi-reader/
 * single-writer topology for load-balanced read scaling. */

#include <stdbool.h>
#include <stddef.h>

#include "picowal_db.h"

/* primary_url must look like "http://host[:port]/prefix/" (matching
 * whatever --picowal-repl-prefix the primary was configured with).
 * write_token is the shared secret to present via X-PW-Write-Token
 * (must match the primary's --picowal-write-token). Spawns a detached
 * background thread; returns false if the URL can't be parsed or the
 * thread can't be started. */
bool picowal_repl_client_start(const char* primary_url, const char* write_token,
                               picowal_db_t* db);

/* True once picowal_repl_client_start() has been called successfully --
 * main.c uses this to keep this node's own /wal/ mutation routes
 * read-only (replicas must not accept local writes; they'd silently
 * diverge from the primary's log). */
bool picowal_replica_mode_enabled(void);

#endif
