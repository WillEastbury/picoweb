#ifndef METAL_PICOWAL_PARTITION_H
#define METAL_PICOWAL_PARTITION_H

/* picowal_partition — virtual-partition sharding on top of a single
 * picowal volume's pack/record ("deck"/"card") key space.
 *
 * Every (pack, record) key is hashed and reduced modulo a fixed number of
 * virtual partitions (default 1000). Ownership of each virtual partition
 * is resolved *independently and deterministically* on every node via
 * rendezvous (Highest Random Weight) hashing over a tenant's configured
 * node set — no coordination traffic is needed for nodes to agree on who
 * owns what, and membership changes only reshuffle ~1/N of partitions
 * (the classic HRW/consistent-hashing property), rather than all of them.
 *
 * Tenants are resolved the same way the rest of api.c already does (the
 * first host-header component / X-PW-Tenant), each mapped to its own set
 * of candidate writer nodes; tenants not present in the map fall back to
 * the global node pool (--picowal-partition-nodes).
 *
 * When a request lands on a node that is NOT the current owner for that
 * request's virtual partition, this module can either:
 *   - "redirect": reply 307 with Location pointing at the owner and a
 *     X-PW-Partition-Owner header, so smart/caching clients can connect
 *     directly next time (Redis Cluster MOVED-style).
 *   - "proxy": transparently forward the request to the owner over a
 *     plain-socket HTTP/1.1 round trip and relay its response back,
 *     so every client can stay pointed at any node in the pool.
 *
 * This is deliberately simple (no per-partition replication or
 * migration protocol -- ownership is *computed*, not migrated data);
 * see README for the operational caveat that a node briefly considered
 * "owner" during a membership change may not yet hold every record for
 * that partition if the pool itself isn't a fully-replicated set. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "http.h"
#include "api.h"

#define PICOWAL_PARTITION_COUNT   1000
#define PICOWAL_PARTITION_NODE_ID_MAX 64

/* Configure partitioning.
 *   self_id        -- this node's own id, "host:port", must appear in
 *                      nodes_csv (and in every tenant list it's meant to
 *                      own partitions in).
 *   nodes_csv      -- comma-separated global node pool, e.g.
 *                      "10.0.0.1:9080,10.0.0.2:9080,10.0.0.3:9080".
 *   tenant_map_csv -- optional; ';'-separated list of
 *                      "tenant=host1:port1|host2:port2|..." entries
 *                      overriding the node set for specific tenants.
 *                      May be NULL/empty to use the global pool for all
 *                      tenants.
 *   mode           -- "redirect" or "proxy" (default "redirect" if NULL
 *                      or unrecognized).
 *   write_token    -- shared secret forwarded on proxied requests.
 * Returns false on bad config (self_id not in nodes_csv, lists too long,
 * malformed tenant_map_csv, etc). */
bool picowal_partition_configure(const char* self_id, const char* nodes_csv,
                                  const char* tenant_map_csv,
                                  const char* mode,
                                  const char* write_token);

bool picowal_partition_enabled(void);
bool picowal_partition_mode_is_proxy(void);

/* Reduce a packed picowal key (picowal_db_pack_key() result) to a virtual
 * partition id in [0, PICOWAL_PARTITION_COUNT). */
uint32_t picowal_partition_of_key(uint32_t key);

/* Resolve the owning node id ("host:port") for a given tenant + virtual
 * partition. tenant may be NULL/empty to use the global pool. Returns
 * false if no candidate nodes are configured at all. */
bool picowal_partition_owner(const char* tenant, size_t tenant_len,
                              uint32_t vpart, char* out, size_t out_cap);

/* True if `owner` (as returned by picowal_partition_owner) refers to this
 * node itself. */
bool picowal_partition_owner_is_self(const char* owner);

/* Build a 307 redirect response pointing at `owner` for the given
 * request path, tagged with X-PW-Partition / X-PW-Partition-Owner
 * headers. */
void picowal_partition_redirect(const char* owner, uint32_t vpart,
                                 const char* path, size_t path_len,
                                 api_resp_t* resp);

/* Forward the request to `owner` over a fresh HTTP/1.1 connection and
 * relay its response verbatim (plus X-PW-Partition/X-PW-Proxied-From
 * headers) into `resp`. Returns false (and fills resp with a 502) if the
 * owner could not be reached within a short timeout. */
bool picowal_partition_proxy(const char* owner, uint32_t vpart,
                              http_method_t method,
                              const char* path, size_t path_len,
                              const char* body, size_t body_len,
                              const char* write_token, size_t write_token_len,
                              const char* cookie, size_t cookie_len,
                              api_resp_t* resp);

#endif
