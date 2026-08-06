/*
 * picowal_fence.h — mandatory control-plane write fence client.
 *
 * When picoweb serves a CLUSTERED picowal volume as the write PRIMARY,
 * every mutation must be authorized by the local picocluster control
 * plane (picowald) before it touches the log. This client speaks a tiny
 * fixed-frame request/response over a local Unix-domain socket
 * (picowald's fence socket) and answers one question: "is this node,
 * right now, still the committed primary for (group, epoch)?"
 *
 * The answer is OK only when the co-located picowald is the current Raft
 * leader with majority contact AND the committed data-group assignment
 * names this node primary at exactly this epoch. A partitioned former
 * primary therefore fails closed: it can no longer prove leadership, so
 * its writes are refused. Authority never comes from gossip or a local
 * file — only from that live control-plane check.
 *
 * A bounded, monotonic lease (<= PWFENCE_CLIENT_LEASE_CAP_MS, always
 * <= 1s) is cached between checks so the hot write path does not pay a
 * socket round-trip per mutation; the lease is only ever granted by the
 * quorum-backed leader and expires on a monotonic clock, never a
 * wall-clock signature.
 *
 * No third-party dependencies: raw AF_UNIX + fixed-size framing.
 */
#ifndef PICOWAL_FENCE_H
#define PICOWAL_FENCE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct picowal_fence picowal_fence_t;

/* Create a fence client for (group, epoch, node_id) that authorizes via
 * picowald's fence socket at `sock_path`. Returns NULL on invalid
 * arguments (all four required). Does not require picowald to be
 * reachable yet — writes fail closed until a live check succeeds. */
picowal_fence_t* picowal_fence_create(const char* sock_path, const char* group,
                                      uint64_t epoch, const char* node_id);
void picowal_fence_destroy(picowal_fence_t* f);

/* Returns true iff a picowal mutation is currently authorized. Uses a
 * bounded monotonic lease cache to avoid a round-trip per write; fails
 * closed (false) on any denial, protocol error, or unreachable control
 * plane. Thread-safe. */
bool picowal_fence_check(picowal_fence_t* f);

/* One-shot probe ignoring the lease cache. Returns the raw fence status
 * byte (0 == authorized) or -1 on transport failure. Used at startup to
 * surface misconfiguration early without blocking writable startup. */
int picowal_fence_probe(picowal_fence_t* f);

#endif /* PICOWAL_FENCE_H */
