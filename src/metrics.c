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

metric_stage_t g_stages[METRICS_STAGE_COUNT];

const resource_t* metrics_health_resource = NULL;
const resource_t* metrics_stats_resource  = NULL;

/* ===========================================================
 * /stats writable response buffer
 *
 * Layout (the body bytes, total = STATS_BODY_LEN):
 *
 *   uptime_seconds=DDDDDDDDDD\n
 *   total_requests=DDDDDDDDDD\n
 *   p95_microseconds=DDDDDDDDDD\n
 *   p98_microseconds=DDDDDDDDDD\n
 *   p99_microseconds=DDDDDDDDDD\n
 *   p999_microseconds=DDDDDDDDDD\n
 *   stage_rx_avg_us=DDDDDDDDDD\n
 *   stage_step_avg_us=DDDDDDDDDD\n
 *   stage_parse_avg_us=DDDDDDDDDD\n
 *   stage_build_avg_us=DDDDDDDDDD\n
 *   stage_seal_avg_us=DDDDDDDDDD\n
 *   stage_nst_avg_us=DDDDDDDDDD\n
 *   stage_tx_avg_us=DDDDDDDDDD\n
 *   window_seconds=300\n
 *
 * Each numeric field is a fixed-width 10-digit zero-padded decimal so
 * the body length never changes (fixed Content-Length, fixed pointer,
 * lock-free in-place updates from the updater thread).
 * =========================================================== */

#define STATS_FIELD_DIGITS 10

/* Helper for the template string below: 10 zero digits. */
#define STATS_DIGITS_STR "0000000000"

/* Each line's size is (key_len + 1 ('=') + 10 (digits) + 1 ('\n')).
 * Keep this layout in lockstep with the offset constants below. */

/* Offsets are computed from the lengths of preceding lines. Update both
 * the template and the OFF_* constants together. */
#define LINE_UPTIME      "uptime_seconds=" STATS_DIGITS_STR "\n"        /*26*/
#define LINE_REQUESTS    "total_requests=" STATS_DIGITS_STR "\n"        /*26*/
#define LINE_P95         "p95_microseconds=" STATS_DIGITS_STR "\n"      /*28*/
#define LINE_P98         "p98_microseconds=" STATS_DIGITS_STR "\n"      /*28*/
#define LINE_P99         "p99_microseconds=" STATS_DIGITS_STR "\n"      /*28*/
#define LINE_P999        "p999_microseconds=" STATS_DIGITS_STR "\n"     /*29*/
#define LINE_STAGE_RX    "stage_rx_avg_us=" STATS_DIGITS_STR "\n"       /*27*/
#define LINE_STAGE_STEP  "stage_step_avg_us=" STATS_DIGITS_STR "\n"     /*29*/
#define LINE_STAGE_PARSE "stage_parse_avg_us=" STATS_DIGITS_STR "\n"    /*30*/
#define LINE_STAGE_BUILD "stage_build_avg_us=" STATS_DIGITS_STR "\n"    /*30*/
#define LINE_STAGE_SEAL  "stage_seal_avg_us=" STATS_DIGITS_STR "\n"     /*29*/
#define LINE_STAGE_NST   "stage_nst_avg_us=" STATS_DIGITS_STR "\n"      /*28*/
#define LINE_STAGE_TX    "stage_tx_avg_us=" STATS_DIGITS_STR "\n"       /*27*/
#define LINE_WINDOW      "window_seconds=300\n"                         /*19*/

#define LINELEN_UPTIME       26u
#define LINELEN_REQUESTS     26u
#define LINELEN_P95          28u
#define LINELEN_P98          28u
#define LINELEN_P99          28u
#define LINELEN_P999         29u
#define LINELEN_STAGE_RX     27u
#define LINELEN_STAGE_STEP   29u
#define LINELEN_STAGE_PARSE  30u
#define LINELEN_STAGE_BUILD  30u
#define LINELEN_STAGE_SEAL   29u
#define LINELEN_STAGE_NST    28u
#define LINELEN_STAGE_TX     27u
#define LINELEN_WINDOW       19u

#define STATS_BODY_LEN (LINELEN_UPTIME + LINELEN_REQUESTS + \
    LINELEN_P95 + LINELEN_P98 + LINELEN_P99 + LINELEN_P999 + \
    LINELEN_STAGE_RX + LINELEN_STAGE_STEP + LINELEN_STAGE_PARSE + \
    LINELEN_STAGE_BUILD + LINELEN_STAGE_SEAL + LINELEN_STAGE_NST + \
    LINELEN_STAGE_TX + LINELEN_WINDOW)

/* Field-start offsets of the 10 digits within each line. Each line
 * looks like "<key>=" followed by 10 digit bytes followed by '\n', so
 * the digits start at (line_offset + line_length - 11). */
#define DIGITS_OFF(line_off, line_len) ((line_off) + (line_len) - 11u)

#define LINE_OFF_UPTIME      0u
#define LINE_OFF_REQUESTS    (LINE_OFF_UPTIME      + LINELEN_UPTIME)
#define LINE_OFF_P95         (LINE_OFF_REQUESTS    + LINELEN_REQUESTS)
#define LINE_OFF_P98         (LINE_OFF_P95         + LINELEN_P95)
#define LINE_OFF_P99         (LINE_OFF_P98         + LINELEN_P98)
#define LINE_OFF_P999        (LINE_OFF_P99         + LINELEN_P99)
#define LINE_OFF_STAGE_RX    (LINE_OFF_P999        + LINELEN_P999)
#define LINE_OFF_STAGE_STEP  (LINE_OFF_STAGE_RX    + LINELEN_STAGE_RX)
#define LINE_OFF_STAGE_PARSE (LINE_OFF_STAGE_STEP  + LINELEN_STAGE_STEP)
#define LINE_OFF_STAGE_BUILD (LINE_OFF_STAGE_PARSE + LINELEN_STAGE_PARSE)
#define LINE_OFF_STAGE_SEAL  (LINE_OFF_STAGE_BUILD + LINELEN_STAGE_BUILD)
#define LINE_OFF_STAGE_NST   (LINE_OFF_STAGE_SEAL  + LINELEN_STAGE_SEAL)
#define LINE_OFF_STAGE_TX    (LINE_OFF_STAGE_NST   + LINELEN_STAGE_NST)

#define OFF_UPTIME       DIGITS_OFF(LINE_OFF_UPTIME,      LINELEN_UPTIME)
#define OFF_REQUESTS     DIGITS_OFF(LINE_OFF_REQUESTS,    LINELEN_REQUESTS)
#define OFF_P95          DIGITS_OFF(LINE_OFF_P95,         LINELEN_P95)
#define OFF_P98          DIGITS_OFF(LINE_OFF_P98,         LINELEN_P98)
#define OFF_P99          DIGITS_OFF(LINE_OFF_P99,         LINELEN_P99)
#define OFF_P999         DIGITS_OFF(LINE_OFF_P999,        LINELEN_P999)
#define OFF_STAGE_RX     DIGITS_OFF(LINE_OFF_STAGE_RX,    LINELEN_STAGE_RX)
#define OFF_STAGE_STEP   DIGITS_OFF(LINE_OFF_STAGE_STEP,  LINELEN_STAGE_STEP)
#define OFF_STAGE_PARSE  DIGITS_OFF(LINE_OFF_STAGE_PARSE, LINELEN_STAGE_PARSE)
#define OFF_STAGE_BUILD  DIGITS_OFF(LINE_OFF_STAGE_BUILD, LINELEN_STAGE_BUILD)
#define OFF_STAGE_SEAL   DIGITS_OFF(LINE_OFF_STAGE_SEAL,  LINELEN_STAGE_SEAL)
#define OFF_STAGE_NST    DIGITS_OFF(LINE_OFF_STAGE_NST,   LINELEN_STAGE_NST)
#define OFF_STAGE_TX     DIGITS_OFF(LINE_OFF_STAGE_TX,    LINELEN_STAGE_TX)

static const char STATS_BODY_TEMPLATE[STATS_BODY_LEN + 1] =
    LINE_UPTIME LINE_REQUESTS
    LINE_P95 LINE_P98 LINE_P99 LINE_P999
    LINE_STAGE_RX LINE_STAGE_STEP LINE_STAGE_PARSE LINE_STAGE_BUILD
    LINE_STAGE_SEAL LINE_STAGE_NST LINE_STAGE_TX
    LINE_WINDOW;

_Static_assert(sizeof(STATS_BODY_TEMPLATE) == STATS_BODY_LEN + 1,
               "STATS_BODY_TEMPLATE length mismatch");

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
 * but inlined here so we don't have to expose the static helper.
 * Does NOT include Connection header or final blank line — the caller
 * appends a shared connection-tail segment at send time. */
static const char* build_head_local(arena_t* arena,
                                    const char* status_line,
                                    const char* mime,
                                    size_t body_len,
                                    const char* date_buf, size_t date_len,
                                    const char* extra_header,
                                    size_t* out_len) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
        "%s\r\n"
        "Server: picoweb\r\n"
        "Date: %.*s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "%s",
        status_line,
        (int)date_len, date_buf,
        mime,
        body_len,
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
        r->head = build_head_local(arena, "HTTP/1.1 200 OK",
            "text/plain; charset=utf-8", 2, date_buf, date_len,
            "Cache-Control: no-store\r\n", &r->head_len);
        metrics_health_resource = r;
    }

    /* /stats */
    {
        resource_t* r = (resource_t*)arena_alloc(arena, sizeof(*r), 64);
        memset(r, 0, sizeof(*r));
        r->body = g_stats_body;          /* writable mmap region */
        r->body_len = STATS_BODY_LEN;
        r->head = build_head_local(arena, "HTTP/1.1 200 OK",
            "text/plain; charset=utf-8", STATS_BODY_LEN,
            date_buf, date_len, "Cache-Control: no-store\r\n",
            &r->head_len);
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

    uint32_t b95  = percentile_bucket(hist, total_samples, 0.95);
    uint32_t b98  = percentile_bucket(hist, total_samples, 0.98);
    uint32_t b99  = percentile_bucket(hist, total_samples, 0.99);
    uint32_t b999 = percentile_bucket(hist, total_samples, 0.999);
    uint64_t p95_us  = ticks_to_us(bucket_to_ticks(b95));
    uint64_t p98_us  = ticks_to_us(bucket_to_ticks(b98));
    uint64_t p99_us  = ticks_to_us(bucket_to_ticks(b99));
    uint64_t p999_us = ticks_to_us(bucket_to_ticks(b999));

    /* Per-stage averages: ticks_total / count, in microseconds.
     * Relaxed loads — torn read of a 64-bit aligned field is impossible
     * on x86-64/aarch64; cross-stage consistency does not matter. */
    uint64_t stage_avg_us[METRICS_STAGE_COUNT];
    for (int s = 0; s < METRICS_STAGE_COUNT; s++) {
        uint64_t sum = __atomic_load_n(&g_stages[s].sum_ticks, __ATOMIC_RELAXED);
        uint64_t cnt = __atomic_load_n(&g_stages[s].count,     __ATOMIC_RELAXED);
        stage_avg_us[s] = cnt ? ticks_to_us(sum / cnt) : 0;
    }

    /* Cap to 10 digits. */
    if (uptime_s   > 9999999999ULL) uptime_s   = 9999999999ULL;
    if (total_reqs > 9999999999ULL) total_reqs = 9999999999ULL;
    if (p95_us     > 9999999999ULL) p95_us     = 9999999999ULL;
    if (p98_us     > 9999999999ULL) p98_us     = 9999999999ULL;
    if (p99_us     > 9999999999ULL) p99_us     = 9999999999ULL;
    if (p999_us    > 9999999999ULL) p999_us    = 9999999999ULL;
    for (int s = 0; s < METRICS_STAGE_COUNT; s++) {
        if (stage_avg_us[s] > 9999999999ULL) stage_avg_us[s] = 9999999999ULL;
    }

    write_digits(OFF_UPTIME,      uptime_s);
    write_digits(OFF_REQUESTS,    total_reqs);
    write_digits(OFF_P95,         p95_us);
    write_digits(OFF_P98,         p98_us);
    write_digits(OFF_P99,         p99_us);
    write_digits(OFF_P999,        p999_us);
    write_digits(OFF_STAGE_RX,    stage_avg_us[METRICS_STAGE_TLS_RX]);
    write_digits(OFF_STAGE_STEP,  stage_avg_us[METRICS_STAGE_TLS_STEP]);
    write_digits(OFF_STAGE_PARSE, stage_avg_us[METRICS_STAGE_TLS_PARSE]);
    write_digits(OFF_STAGE_BUILD, stage_avg_us[METRICS_STAGE_TLS_BUILD]);
    write_digits(OFF_STAGE_SEAL,  stage_avg_us[METRICS_STAGE_TLS_SEAL]);
    write_digits(OFF_STAGE_NST,   stage_avg_us[METRICS_STAGE_TLS_NST]);
    write_digits(OFF_STAGE_TX,    stage_avg_us[METRICS_STAGE_TLS_TX]);
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
