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
#include <stdbool.h>

#include "arena.h"
#include "http.h"
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

/* ===========================================================
 * Per-stage timing
 *
 * Eight named stages are accumulated globally (sum_ticks, count,
 * max_ticks). Single worker today; relaxed atomics make this safe
 * to extend to multi-worker without revisiting hot-path code.
 *
 * Exposed in /stats as <stage>_avg_us. Stage IDs are stable —
 * /stats consumers depend on field order and width.
 * =========================================================== */

enum {
    METRICS_STAGE_TLS_RX     = 0,  /* rx_buf -> rx_ack -> step setup     */
    METRICS_STAGE_TLS_STEP   = 1,  /* pw_tls_step (handshake or NOP)     */
    METRICS_STAGE_TLS_PARSE  = 2,  /* HTTP request parse over plaintext  */
    METRICS_STAGE_TLS_BUILD  = 3,  /* build_http_response_iov            */
    METRICS_STAGE_TLS_SEAL   = 4,  /* pw_tls_app_seal_iov                */
    METRICS_STAGE_TLS_NST    = 5,  /* maybe_emit_session_ticket          */
    METRICS_STAGE_TLS_TX     = 6,  /* tx_buf copy + tx_ack               */
    METRICS_STAGE_COUNT      = 7,
};

typedef struct {
    uint64_t sum_ticks;
    uint64_t count;
    uint64_t max_ticks;
    char     _pad[40];
} __attribute__((aligned(64))) metric_stage_t;

extern metric_stage_t g_stages[METRICS_STAGE_COUNT];

static inline void metrics_stage_add(int s, uint64_t delta_tsc) {
    metric_stage_t* st = &g_stages[s];
    __atomic_add_fetch(&st->sum_ticks, delta_tsc, __ATOMIC_RELAXED);
    __atomic_add_fetch(&st->count,     1,         __ATOMIC_RELAXED);
    uint64_t prev = __atomic_load_n(&st->max_ticks, __ATOMIC_RELAXED);
    while (delta_tsc > prev &&
           !__atomic_compare_exchange_n(&st->max_ticks, &prev, delta_tsc,
                                        false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        /* prev was reloaded by CAS; loop. */
    }
}

typedef enum {
        METRICS_ROUTE_STATIC = 0,
        METRICS_ROUTE_HEALTHZ,
        METRICS_ROUTE_READYZ,
        METRICS_ROUTE_STATS,
        METRICS_ROUTE_METRICSZ,
        METRICS_ROUTE_SCORES_START,
        METRICS_ROUTE_SCORES,
        METRICS_ROUTE_API,
        METRICS_ROUTE_PICOWAL,
        METRICS_ROUTE_OTHER,
        METRICS_ROUTE_COUNT,
} metrics_route_t;

typedef enum {
        METRICS_WAL_READ = 0,
        METRICS_WAL_WRITE,
        METRICS_WAL_DELETE,
        METRICS_WAL_LIST,
        METRICS_WAL_COUNT,
} metrics_wal_op_t;

typedef enum {
        METRICS_SCORE_REJECT_RATE_LIMITED = 0,
        METRICS_SCORE_REJECT_INVALID_TOKEN,
        METRICS_SCORE_REJECT_INVALID_BODY,
        METRICS_SCORE_REJECT_METHOD,
        METRICS_SCORE_REJECT_UNAVAILABLE,
        METRICS_SCORE_REJECT_DRAINING,
        METRICS_SCORE_REJECT_WRITE_FAILED,
        METRICS_SCORE_REJECT_TOKEN_ISSUE_FAILED,
        METRICS_SCORE_REJECT_COUNT,
} metrics_score_reject_t;

metrics_route_t metrics_route_for_path(const char* path, size_t path_len);
const char* metrics_route_name(metrics_route_t route);

void metrics_observe_request(metrics_route_t route,
                             http_method_t method,
                             int status,
                             uint64_t latency_tsc,
                             size_t request_bytes,
                             size_t response_plaintext_bytes,
                             const char* client_ip,
                             bool aborted);

void metrics_observe_picowal(metrics_wal_op_t op,
                             uint64_t lock_wait_tsc,
                             uint64_t storage_tsc,
                             bool ok);

void metrics_score_reject(metrics_score_reject_t reason);

void metrics_set_picowal_recovery(uint64_t status_code,
                                  uint64_t records_scanned,
                                  uint64_t records_recovered,
                                  uint64_t corrupt_records,
                                  uint64_t truncated_records,
                                  uint64_t truncated_bytes,
                                  uint64_t write_offset,
                                  uint64_t volume_bytes);

char* metrics_render_text(size_t* out_len);

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
