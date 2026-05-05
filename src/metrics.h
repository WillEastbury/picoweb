#ifndef METAL_METRICS_H
#define METAL_METRICS_H

/* Per-worker latency metrics + /health and /stats endpoints.
 *
 * Hot path additions (per request):
 *   1. A single rdtsc / mrs cntvct_el0 read at request start (in dispatch_one).
 *   2. A second TSC read at "fully sent" (in try_send when complete).
 *   3. metrics_record(): one ++ on a per-worker histogram bucket and
 *      one ++ on per-worker total counter. Per-worker memory is owned
 *      exclusively by one thread — zero atomics, zero contention.
 *
 * The hot path does NOT touch /stats response memory: that's mutated
 * by a background thread once per second. The hot path reads
 * (head_keepalive, head_keepalive_len) like any other resource.
 *
 * /health is fully static (body "OK"). Inserted into the flat hash
 * table for every host so flat_lookup finds it with no extra branches.
 *
 * /stats body length is fixed (METRICS_BODY_LEN) so neither pointer
 * nor length ever changes after registration — only the digit bytes
 * inside the body are overwritten in-place. A reader racing with the
 * updater can at worst see a single digit half-updated, which still
 * decodes to a valid integer (just slightly wrong). No locks needed.
 */

#include <stdint.h>
#include <stddef.h>

#include "arena.h"
#include "jumptable.h"

#define METRICS_WINDOW_SEC 300                /* 5-minute rolling window */
/* HdrHistogram-style buckets: 8 sub-buckets per power-of-two octave
 * gives ~12% precision (2^(1/8)=1.09). 64 octaves max. Bucket 0..7
 * is the linear region (each bucket = 1 tick), 8..63*8+7=511 covers
 * ticks up to 2^63 (~3 centuries at 1GHz). Most buckets are unused —
 * memory is per-worker so 4 workers × 300s × 512 buckets × 4B = 2.4MB. */
#define METRICS_SUB_BITS   3
#define METRICS_SUB_COUNT  (1u << METRICS_SUB_BITS)             /* 8   */
#define METRICS_OCTAVES    64
#define METRICS_BUCKETS    (METRICS_OCTAVES * METRICS_SUB_COUNT) /* 512 */

/* Per-worker writable metrics. Owned exclusively by one worker thread.
 * Read concurrently by the updater thread — torn reads are tolerated
 * (worst case: a histogram bucket count is one off for one second). */
typedef struct {
    uint64_t total_requests;
    uint64_t cur_second;          /* monotonic seconds since metrics_init */
    uint32_t hist[METRICS_WINDOW_SEC][METRICS_BUCKETS];
    char     _pad[64];
} __attribute__((aligned(64))) metrics_t;

extern uint64_t   g_tsc_per_sec;
extern uint64_t   g_tsc_start;
extern int64_t    g_start_ms;
extern metrics_t* g_metrics;
extern int        g_n_workers;

/* Per-thread pointer to its own metrics_t. Set in server_run() so the
 * hot path can use metrics_record(g_worker_metrics, ...) without
 * threading the pointer through every helper. */
extern __thread metrics_t* g_worker_metrics;

/* Initialize metrics (TSC calibration, mmap workers' arrays).
 * Must be called BEFORE jumptable_build() so /stats body buffer
 * exists when register_special_endpoints runs. */
void metrics_init(int n_workers);

/* Spawn the background stats updater thread.
 * Safe to call after workers are running. */
void metrics_start_updater(void);

/* Resources inserted into every host bucket of the flat table.
 * Pointers are valid after metrics_init() has run. */
extern const resource_t* metrics_health_resource;
extern const resource_t* metrics_stats_resource;

/* Called by jumptable_build during construction to materialize the
 * /health and /stats resources. Builds the heads via the supplied
 * arena; the /stats body lives in a separate writable mmap region
 * owned by the metrics module. After this returns, the resource_t
 * pointers above are valid and can be inserted into the flat table. */
void metrics_build_resources(arena_t* arena,
                             const char* date_buf, size_t date_len);

/* TSC primitive — inlined into the hot path. */
static inline uint64_t metal_tsc(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | (uint64_t)lo;
#elif defined(__aarch64__)
    uint64_t v;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    /* Portable fallback. Slower but functional. */
    extern uint64_t metal_tsc_fallback(void);
    return metal_tsc_fallback();
#endif
}

/* Map a delta (in TSC ticks) to a histogram bucket. Bucket b covers
 * ticks in [2^b, 2^(b+1)). Bucket 0 covers [0, 2). */
static inline uint32_t metrics_bucket_for_tsc(uint64_t delta_tsc) {
    if (delta_tsc < 2) return 0;
    uint32_t b = 63u - (uint32_t)__builtin_clzll(delta_tsc);
    if (b >= METRICS_BUCKETS) b = METRICS_BUCKETS - 1u;
    return b;
}

/* Hot-path: record one request. Caller passes its per-worker metrics. */
static inline void metrics_record(metrics_t* m,
                                  uint64_t start_tsc, uint64_t end_tsc) {
    uint64_t cur_sec = (end_tsc - g_tsc_start) / g_tsc_per_sec;
    uint32_t slot = (uint32_t)(cur_sec % METRICS_WINDOW_SEC);
    if (__builtin_expect(m->cur_second != cur_sec, 0)) {
        /* Advance windows: zero every slot from prev+1 .. cur_sec.
         * If we jumped >= a full window, just zero everything. */
        uint64_t prev = m->cur_second;
        if (cur_sec - prev >= METRICS_WINDOW_SEC) {
            __builtin_memset(m->hist, 0, sizeof(m->hist));
        } else {
            for (uint64_t s = prev + 1; s <= cur_sec; s++) {
                __builtin_memset(m->hist[s % METRICS_WINDOW_SEC], 0,
                                 sizeof(m->hist[0]));
            }
        }
        m->cur_second = cur_sec;
    }
    uint32_t b = metrics_bucket_for_tsc(end_tsc - start_tsc);
    m->hist[slot][b]++;
    m->total_requests++;
}

#endif /* METAL_METRICS_H */
