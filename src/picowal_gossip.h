#ifndef METAL_PICOWAL_GOSSIP_H
#define METAL_PICOWAL_GOSSIP_H

/* picowal_gossip — a small, deliberately simple gossip-based leader
 * election for a picowal replica set, layered on top of picowal_repl /
 * picowal_repl_client.
 *
 * Model: a fixed, statically-configured set of "registered followers"
 * (--picowal-followers=host1:port1,host2:port2,...), each running this
 * module with its own identity (--picowal-node-id=host:port, which must
 * be one of the entries in --picowal-followers). Every follower is
 * itself a picowal_repl_client replica of some primary.
 *
 * Each follower periodically checks whether its primary looks healthy
 * (picowal_repl_client_primary_healthy()). While healthy, nothing
 * happens. Once a follower sees its primary go unhealthy (a run of
 * consecutive failed status polls), it starts an election: it
 * deterministically nominates a single candidate (the lexicographically
 * smallest NON-BLACKLISTED id among the registered followers -- see
 * "dead-candidate exclusion" below -- this makes every
 * correctly-functioning follower converge on the *same* candidate for a
 * given election without needing a real leader-election algorithm), and
 * gossips that vote to every other registered follower via
 * `POST {prefix}vote` (best-effort, fire-and-forget, short timeout).
 *
 * Each follower tallies votes for the current (term, candidate) pair.
 * The moment ANY follower observes that a candidate has been voted for
 * by *more than 50% of the registered followers* (strictly greater than
 * half of len(--picowal-followers)), it records that candidate as the
 * known leader (symmetric -- see "symmetric leader confirmation" below)
 * and, if that candidate is itself, self-promotes:
 *   - stops its own repl-client polling (picowal_repl_client_stop())
 *   - flips its local picowal volume back to read-write
 *     (picowal_db_set_read_only(db, false))
 *   - starts serving the primary-side replication feed
 *     (picowal_repl_init()) so the other followers can re-point at it
 *
 * Two behaviors closing real gaps in an earlier version of this design
 * (found while porting this exact protocol to another service and
 * testing it end-to-end against real multi-node failure scenarios --
 * both are necessary for a cluster to survive MORE THAN ONE leader
 * failure over its lifetime, not just the very first one):
 *
 *   - Dead-candidate exclusion: pick_candidate() excludes any follower
 *     id already conclusively shown unhealthy (g_dead[]) while it was
 *     the known leader. Without this, once the alphabetically-smallest
 *     follower id has been elected and later ALSO dies (an entirely
 *     normal event), every remaining follower would keep re-nominating
 *     that SAME dead node on every subsequent health-check failure
 *     forever (plain lexicographic order never changes) -- nobody can
 *     ever vote a dead node back into quorum, so the cluster would
 *     simply never recover past the second leader failure.
 *   - Symmetric leader confirmation + dynamic retargeting: the moment
 *     ANY follower observes quorum for a candidate, it records that
 *     candidate as g_known_leader and (if the candidate isn't itself)
 *     calls picowal_repl_client_retarget() to start following it --
 *     not just the winning candidate learning it won. The original
 *     design only handled self-promotion, leaving every OTHER follower
 *     with no mechanism to ever learn a new leader had been elected
 *     (their repl_client stayed pointed at whatever --picowal-replica-of
 *     was originally configured with). Vote tallying is inherently
 *     symmetric -- every follower can independently count the same
 *     ballots -- so there's no reason only the winner should act on it.
 *
 * This is deliberately NOT a full consensus protocol (no log-matching,
 * no fencing tokens, no protection against a stale primary reappearing
 * mid-election and both nodes accepting writes). It is a pragmatic
 * quorum-based promotion mechanism suitable for "mostly cooperative"
 * failover -- see README for the split-brain caveat. */

#include <stdbool.h>
#include <stddef.h>

#include "http.h"
#include "api.h"
#include "picowal_db.h"

/* Configure and start the gossip thread.
 *   self_id       -- this node's own id, must be one of the entries in
 *                     followers_csv (e.g. "127.0.0.1:9102").
 *   followers_csv -- comma-separated list of all registered followers'
 *                     ids, e.g. "127.0.0.1:9102,127.0.0.1:9103".
 *   write_token   -- shared secret reused from --picowal-write-token,
 *                     presented via X-PW-Write-Token on gossip requests.
 *   db            -- this node's picowal volume (flipped read-write on
 *                     promotion).
 *   repl_prefix   -- prefix to use for picowal_repl_init() if/when this
 *                     node is promoted to leader (e.g. "/repl/").
 * Returns false on bad config (self_id not in followers_csv, list too
 * long, etc). */
bool picowal_gossip_init(const char* self_id, const char* followers_csv,
                          const char* write_token, picowal_db_t* db,
                          const char* repl_prefix);

bool picowal_gossip_enabled(void);
bool picowal_gossip_path_matches(const char* path, size_t path_len);

void picowal_gossip_dispatch(http_method_t method,
                              const char* path, size_t path_len,
                              const char* body, size_t body_len,
                              const char* write_token, size_t write_token_len,
                              api_resp_t* resp);

/* True once this node has self-promoted to leader/writer via gossip
 * quorum. */
bool picowal_gossip_is_leader(void);

#endif
