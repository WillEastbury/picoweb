#include "metrics.h"
#include "util.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

/* ===========================================================
 * Globals
 * =========================================================== */

uint64_t   g_tsc_per_sec = 1;
uint64_t   g_tsc_start   = 0;
int64_t    g_start_ms    = 0;
metrics_t* g_metrics     = NULL;
int        g_n_workers   = 0;

__thread metrics_t* g_worker_metrics = NULL;

const resource_t* metrics_health_resource = NULL;
const resource_t* metrics_stats_resource  = NULL;

/* ===========================================================
 * /stats writable response buffer
 *
 * Layout (the body bytes, total = METRICS_STATS_BODY_LEN = 127):
 *
 *   uptime_seconds=DDDDDDDDDD\n        offset 0..25  (digits at 15..24)
 *   total_requests=DDDDDDDDDD\n        offset 26..51 (digits at 41..50)
 *   p95_microseconds=DDDDDDDDDD\n      offset 52..79 (digits at 69..78)
 *   p98_microseconds=DDDDDDDDDD\n      offset 80..107 (digits at 97..106)
 *   window_seconds=300\n               offset 108..126
 *
 * Each numeric field is a fixed-width 10-digit zero-padded decimal.
 * Field widths chosen so total length is constant 127 and each field
 * holds plausible upper bounds (uptime 317y, requests 10B, latency
 * ~2.78h in µs).
 * =========================================================== */

#define STATS_BODY_LEN     127
#define STATS_FIELD_DIGITS 10

#define OFF_UPTIME   15
#define OFF_REQUESTS 41
#define OFF_P95      69
#define OFF_P98      97

static const char STATS_BODY_TEMPLATE[STATS_BODY_LEN + 1] =
    "uptime_seconds=0000000000\n"        /* 26 */
    "total_requests=0000000000\n"        /* 26 */
    "p95_microseconds=0000000000\n"      /* 28 */
    "p98_microseconds=0000000000\n"      /* 28 */
    "window_seconds=300\n";              /* 19 */

/* The single writable body buffer. Pointed-to by metrics_stats_resource->body.
 * Length is fixed (STATS_BODY_LEN). Bytes are overwritten in-place by the
 * updater thread. Hot-path reads sendmsg this buffer through the iovec. */
static char* g_stats_body = NULL;

/* ===========================================================
 * TSC calibration
 * =========================================================== */

static void calibrate_tsc(void) {
    struct timespec t0, t1;
    uint64_t tsc0, tsc1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    tsc0 = metal_tsc();

    /* Sleep ~100 ms — long enough for a stable measurement, short
     * enough to not delay startup noticeably. */
    struct timespec slp = { 0, 100 * 1000 * 1000 };
    nanosleep(&slp, NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    tsc1 = metal_tsc();

    uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    uint64_t dt = tsc1 - tsc0;
    if (ns == 0 || dt == 0) {
        /* Pathological — assume TSC ticks at 1 GHz so uptime math
         * doesn't divide by zero. */
        g_tsc_per_sec = 1000000000ULL;
    } else {
        long double s = (long double)dt * 1.0e9L / (long double)ns;
        g_tsc_per_sec = (uint64_t)s;
    }
    g_tsc_start = metal_tsc();
}

/* Portable fallback for non-x86, non-aarch64 targets. */
uint64_t metal_tsc_fallback(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ===========================================================
 * Init
 * =========================================================== */

void metrics_init(int n_workers) {
    g_start_ms = metal_now_ms();
    calibrate_tsc();

    size_t bytes = (size_t)n_workers * sizeof(metrics_t);
    void* p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) metal_die("mmap metrics array");
    g_metrics = (metrics_t*)p;
    g_n_workers = n_workers;

    /* Allocate the writable /stats body buffer (single page is plenty). */
    void* sp = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sp == MAP_FAILED) metal_die("mmap stats body");
    g_stats_body = (char*)sp;
    memcpy(g_stats_body, STATS_BODY_TEMPLATE, STATS_BODY_LEN);

    metal_log("metrics: %d worker(s), tsc/sec=%lu",
              n_workers, (unsigned long)g_tsc_per_sec);
}

/* ===========================================================
 * Resource construction
 * =========================================================== */

/* Build a head string in arena. Same shape as jumptable.c's build_head
 * but inlined here so we don't have to expose the static helper. */
static const char* build_head_local(arena_t* arena,
                                    const char* status_line,
                                    const char* mime,
                                    size_t body_len,
                                    bool keep_alive,
                                    const char* date_buf, size_t date_len,
                                    const char* extra_header,
                                    size_t* out_len) {
    char buf[1280];
    int n = snprintf(buf, sizeof(buf),
        "%s\r\n"
        "Server: picoweb\r\n"
        "Date: %.*s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "%s"
        "\r\n",
        status_line,
        (int)date_len, date_buf,
        mime,
        body_len,
        keep_alive ? "keep-alive" : "close",
        extra_header ? extra_header : "");
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        metal_die("metrics head too long for %s", status_line);
    }
    *out_len = (size_t)n;
    char* dst = (char*)arena_alloc(arena, (size_t)n, 64);
    memcpy(dst, buf, (size_t)n);
    return (const char*)dst;
}

/* Build /health and /stats resource_t structs in the supplied arena.
 * Bodies live elsewhere:
 *   /health body: a static string literal (.rodata)
 *   /stats body : the writable g_stats_body region
 */
void metrics_build_resources(arena_t* arena,
                             const char* date_buf, size_t date_len) {
    if (!g_stats_body) metal_die("metrics_build_resources: metrics_init not called");

    /* /health */
    {
        static const char health_body[] = "OK";
        resource_t* r = (resource_t*)arena_alloc(arena, sizeof(*r), 64);
        memset(r, 0, sizeof(*r));
        r->body = health_body;
        r->body_len = 2;
        r->head_close = build_head_local(arena, "HTTP/1.1 200 OK",
            "text/plain; charset=utf-8", 2, false, date_buf, date_len,
            "Cache-Control: no-store\r\n", &r->head_close_len);
        r->head_keepalive = build_head_local(arena, "HTTP/1.1 200 OK",
            "text/plain; charset=utf-8", 2, true, date_buf, date_len,
            "Cache-Control: no-store\r\n", &r->head_keepalive_len);
        metrics_health_resource = r;
    }

    /* /stats */
    {
        resource_t* r = (resource_t*)arena_alloc(arena, sizeof(*r), 64);
        memset(r, 0, sizeof(*r));
        r->body = g_stats_body;          /* writable mmap region */
        r->body_len = STATS_BODY_LEN;
        r->head_close = build_head_local(arena, "HTTP/1.1 200 OK",
            "text/plain; charset=utf-8", STATS_BODY_LEN, false,
            date_buf, date_len, "Cache-Control: no-store\r\n",
            &r->head_close_len);
        r->head_keepalive = build_head_local(arena, "HTTP/1.1 200 OK",
            "text/plain; charset=utf-8", STATS_BODY_LEN, true,
            date_buf, date_len, "Cache-Control: no-store\r\n",
            &r->head_keepalive_len);
        metrics_stats_resource = r;
    }
}

/* ===========================================================
 * Updater thread
 * =========================================================== */

/* Write a fixed-width 10-digit zero-padded decimal at offset within
 * the writable body. Each digit byte is written individually so a
 * concurrent reader sees, at worst, a half-old/half-new digit pair —
 * still a valid integer. */
static void write_digits(size_t off, uint64_t v) {
    char tmp[STATS_FIELD_DIGITS];
    for (int i = STATS_FIELD_DIGITS - 1; i >= 0; i--) {
        tmp[i] = (char)('0' + (v % 10));
        v /= 10;
    }
    /* memcpy below is byte-wise on these short ranges; valid. */
    memcpy(g_stats_body + off, tmp, STATS_FIELD_DIGITS);
}

/* Sum a field across all workers. Plain reads of uint64 — torn reads
 * on aligned 64-bit are not possible on x86-64/aarch64 so any single
 * worker's contribution is consistent; cross-worker sum is naturally
 * an instantaneous snapshot. */
static uint64_t sum_total_requests(void) {
    uint64_t s = 0;
    for (int w = 0; w < g_n_workers; w++) {
        s += g_metrics[w].total_requests;
    }
    return s;
}

/* Walk every worker's histogram across the rolling 5-min window,
 * accumulating per-bucket totals. Returns total sample count via
 * out_total. */
static void aggregate_histogram(uint64_t out_hist[METRICS_BUCKETS],
                                uint64_t* out_total) {
    memset(out_hist, 0, sizeof(uint64_t) * METRICS_BUCKETS);
    uint64_t total = 0;
    for (int w = 0; w < g_n_workers; w++) {
        const metrics_t* m = &g_metrics[w];
        for (uint32_t s = 0; s < METRICS_WINDOW_SEC; s++) {
            for (uint32_t b = 0; b < METRICS_BUCKETS; b++) {
                uint32_t c = m->hist[s][b];
                out_hist[b] += c;
                total += c;
            }
        }
    }
    *out_total = total;
}

/* Cumulative bucket walk to find the bucket whose cumulative count
 * crosses the target percentile. Returns bucket index, or 0 if total==0. */
static uint32_t percentile_bucket(const uint64_t hist[METRICS_BUCKETS],
                                  uint64_t total, double pct) {
    if (total == 0) return 0;
    uint64_t target = (uint64_t)((double)total * pct);
    if (target == 0) target = 1;
    uint64_t cum = 0;
    for (uint32_t b = 0; b < METRICS_BUCKETS; b++) {
        cum += hist[b];
        if (cum >= target) return b;
    }
    return METRICS_BUCKETS - 1;
}

/* Convert bucket index back to representative tick count (mid-bucket). */
static uint64_t bucket_to_ticks(uint32_t b) {
    if (b == 0) return 1;
    /* Bucket b covers [2^b, 2^(b+1)). Midpoint ~ 1.5 * 2^b. */
    return ((uint64_t)1 << b) + ((uint64_t)1 << (b > 0 ? b - 1 : 0));
}

static uint64_t ticks_to_us(uint64_t ticks) {
    /* ticks * 1e6 / tsc_per_sec, with overflow guard. */
    if (g_tsc_per_sec == 0) return 0;
    long double us = (long double)ticks * 1000000.0L / (long double)g_tsc_per_sec;
    if (us < 0) us = 0;
    if (us > (long double)9999999999ULL) us = 9999999999ULL;
    return (uint64_t)us;
}

static void rebuild_stats_body(void) {
    int64_t now_ms = metal_now_ms();
    uint64_t uptime_s = (uint64_t)((now_ms - g_start_ms) / 1000);
    uint64_t total_reqs = sum_total_requests();

    uint64_t hist[METRICS_BUCKETS];
    uint64_t total_samples = 0;
    aggregate_histogram(hist, &total_samples);

    uint32_t b95 = percentile_bucket(hist, total_samples, 0.95);
    uint32_t b98 = percentile_bucket(hist, total_samples, 0.98);
    uint64_t p95_us = ticks_to_us(bucket_to_ticks(b95));
    uint64_t p98_us = ticks_to_us(bucket_to_ticks(b98));

    /* Cap to 10 digits. */
    if (uptime_s   > 9999999999ULL) uptime_s   = 9999999999ULL;
    if (total_reqs > 9999999999ULL) total_reqs = 9999999999ULL;
    if (p95_us     > 9999999999ULL) p95_us     = 9999999999ULL;
    if (p98_us     > 9999999999ULL) p98_us     = 9999999999ULL;

    write_digits(OFF_UPTIME,   uptime_s);
    write_digits(OFF_REQUESTS, total_reqs);
    write_digits(OFF_P95,      p95_us);
    write_digits(OFF_P98,      p98_us);
}

static void* updater_main(void* arg) {
    (void)arg;
    /* Initial snapshot so /stats is meaningful from second 1. */
    rebuild_stats_body();
    for (;;) {
        struct timespec slp = { 1, 0 };
        nanosleep(&slp, NULL);
        rebuild_stats_body();
    }
    return NULL;
}

void metrics_start_updater(void) {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, updater_main, NULL) != 0) {
        metal_die("pthread_create updater");
    }
    pthread_attr_destroy(&attr);
}
