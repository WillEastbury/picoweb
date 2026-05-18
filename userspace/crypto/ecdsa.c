#include "ecdsa.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/random.h>
#include <sched.h>

#include "hmac.h"
#include "p256.h"
#include "sha256.h"
#include "util.h"

__extension__ typedef unsigned __int128 uint128_t;
typedef struct { uint64_t v[4]; } u256;

static const u256 P256_N = {{
    UINT64_C(0xf3b9cac2fc632551), UINT64_C(0xbce6faada7179e84),
    UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffff00000000)
}};

static uint64_t ct_is_zero_u64(uint64_t x) { return ((x | (0u - x)) >> 63) ^ 1u; }
static uint64_t ct_mask(uint64_t bit) { return 0u - (bit & 1u); }

static uint64_t u256_is_zero(const u256* a) {
    return ct_is_zero_u64(a->v[0] | a->v[1] | a->v[2] | a->v[3]);
}

static void u256_cmov(u256* r, const u256* a, uint64_t bit) {
    uint64_t m = ct_mask(bit);
    for (int i = 0; i < 4; i++) r->v[i] = (r->v[i] & ~m) | (a->v[i] & m);
}

static uint64_t u256_add_raw(u256* r, const u256* a, const u256* b) {
    uint128_t c = 0;
    for (int i = 0; i < 4; i++) {
        c += (uint128_t)a->v[i] + b->v[i];
        r->v[i] = (uint64_t)c;
        c >>= 64;
    }
    return (uint64_t)c;
}

static uint64_t u256_sub_raw(u256* r, const u256* a, const u256* b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t bi = b->v[i];
        uint64_t ri = a->v[i] - bi - borrow;
        uint64_t b1 = (a->v[i] < bi) ? 1u : 0u;
        uint64_t b2 = (borrow && a->v[i] == bi) ? 1u : 0u;
        r->v[i] = ri;
        borrow = b1 | b2;
    }
    return borrow;
}

static uint64_t u256_ge(const u256* a, const u256* b) {
    u256 tmp;
    return u256_sub_raw(&tmp, a, b) ^ 1u;
}

static void mod_add(u256* r, const u256* a, const u256* b) {
    u256 s, t;
    uint64_t carry = u256_add_raw(&s, a, b);
    uint64_t borrow = u256_sub_raw(&t, &s, &P256_N);
    uint64_t use_s = borrow & (carry ^ 1u);
    *r = t;
    u256_cmov(r, &s, use_s);
}

static void mod_mul(u256* r, const u256* a, const u256* b) {
    uint64_t prod[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint128_t c = (uint128_t)a->v[i] * b->v[j] + prod[i + j] + carry;
            prod[i + j] = (uint64_t)c;
            carry = c >> 64;
        }
        for (int k = i + 4; k < 8; k++) {
            uint128_t c = (uint128_t)prod[k] + carry;
            prod[k] = (uint64_t)c;
            carry = c >> 64;
        }
    }

    u256 rem = {{0,0,0,0}};
    for (int bit = 511; bit >= 0; bit--) {
        uint64_t in_bit = (prod[bit / 64] >> (bit % 64)) & 1u;
        uint64_t carry = rem.v[3] >> 63;
        rem.v[3] = (rem.v[3] << 1) | (rem.v[2] >> 63);
        rem.v[2] = (rem.v[2] << 1) | (rem.v[1] >> 63);
        rem.v[1] = (rem.v[1] << 1) | (rem.v[0] >> 63);
        rem.v[0] = (rem.v[0] << 1) | in_bit;
        u256 sub;
        (void)u256_sub_raw(&sub, &rem, &P256_N);
        u256_cmov(&rem, &sub, carry | u256_ge(&rem, &P256_N));
    }
    *r = rem;
}

static void mod_sqr(u256* r, const u256* a) { mod_mul(r, a, a); }
static void mod_from_u64(u256* r, uint64_t x) { r->v[0] = x; r->v[1] = r->v[2] = r->v[3] = 0; }

static void scalar_inv(u256* r, const u256* a) {
    static const u256 exp = {{
        UINT64_C(0xf3b9cac2fc63254f), UINT64_C(0xbce6faada7179e84),
        UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffff00000000)
    }};
    u256 z; mod_from_u64(&z, 1);
    for (int i = 255; i >= 0; i--) {
        mod_sqr(&z, &z);
        if ((exp.v[i / 64] >> (i % 64)) & 1u) mod_mul(&z, &z, a);
    }
    *r = z;
}

static void u256_from_be(u256* r, const uint8_t in[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++) w = (w << 8) | in[(3 - i) * 8 + j];
        r->v[i] = w;
    }
}

static void u256_to_be(const u256* a, uint8_t out[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = a->v[3 - i];
        for (int j = 0; j < 8; j++) out[i * 8 + j] = (uint8_t)(w >> (56 - 8 * j));
    }
}

static int scalar_from_be_checked(u256* r, const uint8_t in[32]) {
    u256_from_be(r, in);
    if (u256_is_zero(r) || u256_ge(r, &P256_N)) return -1;
    return 0;
}

static void scalar_reduce_once(u256* r) {
    u256 t;
    uint64_t borrow = u256_sub_raw(&t, r, &P256_N);
    u256_cmov(r, &t, borrow ^ 1u);
}

static void bits2octets(const uint8_t h[32], uint8_t out[32]) {
    u256 z;
    u256_from_be(&z, h);
    scalar_reduce_once(&z);
    u256_to_be(&z, out);
}

static void hmac_update_byte(hmac_sha256_ctx* h, uint8_t b) {
    hmac_sha256_update(h, &b, 1);
}

static void rfc6979_next(uint8_t K[32], uint8_t V[32], const uint8_t x[32],
                         const uint8_t h1oct[32], uint8_t tag) {
    hmac_sha256_ctx h;
    hmac_sha256_init(&h, K, 32);
    hmac_sha256_update(&h, V, 32);
    hmac_update_byte(&h, tag);
    hmac_sha256_update(&h, x, 32);
    hmac_sha256_update(&h, h1oct, 32);
    hmac_sha256_final(&h, K);
    hmac_sha256(K, 32, V, 32, V);
}

static int rfc6979_generate_k(uint8_t K[32], uint8_t V[32], uint8_t out_k[32]) {
    for (unsigned tries = 0; tries < 1000; tries++) {
        hmac_sha256(K, 32, V, 32, V);
        u256 k;
        if (scalar_from_be_checked(&k, V) == 0) {
            memcpy(out_k, V, 32);
            secure_zero(&k, sizeof(k));
            return 0;
        }
        hmac_sha256_ctx h;
        hmac_sha256_init(&h, K, 32);
        hmac_sha256_update(&h, V, 32);
        hmac_update_byte(&h, 0x00);
        hmac_sha256_final(&h, K);
        hmac_sha256(K, 32, V, 32, V);
    }
    return -1;
}

/* ============================================================== *
 *  ECDSA-P256 precompute pool + producer thread
 * ============================================================== *
 * See ecdsa.h for the rationale. All state is process-singleton.
 * The producer thread is the only writer; sign() is the only reader.
 * A single pthread_mutex protects the ring; condvars handle the
 * not-empty / not-full edges. Counters are atomic so observers
 * (stats endpoints) can read them without taking the ring mutex.
 */

typedef struct {
    uint8_t r[32];
    uint8_t kinv[32];
} ecdsa_precomp_slot_t;

typedef struct {
    ecdsa_precomp_slot_t* slots;
    uint32_t cap;
    uint32_t head;            /* consumer pops here */
    uint32_t tail;            /* producer pushes here */
    uint32_t depth;
    pthread_mutex_t mtx;
    pthread_cond_t  not_full;
    pthread_cond_t  not_empty;
    pthread_t       producer_tid;
    int             producer_started;
    int             shutdown;

    /* Counters (atomic for lock-free reads from stats path) */
    _Atomic uint32_t high_water;
    _Atomic uint64_t hits;
    _Atomic uint64_t misses;
    _Atomic uint64_t produced;
    _Atomic uint64_t producer_errors;
    _Atomic uint64_t s_zero_fallbacks;
} ecdsa_precomp_pool_t;

static ecdsa_precomp_pool_t g_precomp;
static pthread_once_t g_precomp_once = PTHREAD_ONCE_INIT;

static void ecdsa_precomp_global_static_init(void) {
    /* PTHREAD_*_INITIALIZER would be nicer but the struct is BSS so
     * we initialise the mutex/conds explicitly the first time someone
     * touches the pool. Done once-and-only-once via pthread_once. */
    pthread_mutex_init(&g_precomp.mtx, NULL);
    pthread_cond_init(&g_precomp.not_full, NULL);
    pthread_cond_init(&g_precomp.not_empty, NULL);
}

/* Fill exactly `n` bytes from getrandom(), retrying short reads and
 * EINTR. Returns 0 on success, -1 on any unrecoverable error. */
static int ecdsa_precomp_getrandom_full(uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(buf + got, n - got, 0);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

/* Generate one (r, kinv) tuple using rejection sampling for k.
 * Never reduces random bytes modulo n (which would introduce bias).
 * Returns 0 on success, -1 on unrecoverable failure. */
static int ecdsa_precomp_generate_tuple(uint8_t out_r[32], uint8_t out_kinv[32]) {
    for (unsigned tries = 0; tries < 64; tries++) {
        uint8_t kbytes[32];
        if (ecdsa_precomp_getrandom_full(kbytes, sizeof(kbytes)) != 0) {
            secure_zero(kbytes, sizeof(kbytes));
            return -1;
        }
        u256 k;
        if (scalar_from_be_checked(&k, kbytes) != 0) {
            /* k == 0 or k >= n. Resample. */
            secure_zero(kbytes, sizeof(kbytes));
            continue;
        }
        uint8_t xy[64];
        if (p256_scalar_mul_base(kbytes, xy) != 0) {
            secure_zero(kbytes, sizeof(kbytes));
            secure_zero(&k, sizeof(k));
            continue;
        }
        u256 r;
        u256_from_be(&r, xy);
        scalar_reduce_once(&r);
        if (u256_is_zero(&r)) {
            secure_zero(kbytes, sizeof(kbytes));
            secure_zero(&k, sizeof(k));
            secure_zero(xy, sizeof(xy));
            continue;
        }
        u256 kinv;
        scalar_inv(&kinv, &k);
        u256_to_be(&r, out_r);
        u256_to_be(&kinv, out_kinv);
        secure_zero(kbytes, sizeof(kbytes));
        secure_zero(&k, sizeof(k));
        secure_zero(&kinv, sizeof(kinv));
        secure_zero(xy, sizeof(xy));
        return 0;
    }
    return -1;
}

/* Non-blocking try-pop. Returns 0 if a tuple was popped, -1 on
 * empty / not-initialised / contended. NEVER blocks the caller. */
static int ecdsa_precomp_try_pop(uint8_t out_r[32], uint8_t out_kinv[32]) {
    if (!g_precomp.slots) return -1;
    if (pthread_mutex_trylock(&g_precomp.mtx) != 0) return -1;
    if (g_precomp.depth == 0) {
        pthread_mutex_unlock(&g_precomp.mtx);
        return -1;
    }
    ecdsa_precomp_slot_t* sl = &g_precomp.slots[g_precomp.head];
    memcpy(out_r, sl->r, 32);
    memcpy(out_kinv, sl->kinv, 32);
    secure_zero(sl, sizeof(*sl));
    g_precomp.head = (g_precomp.head + 1) % g_precomp.cap;
    g_precomp.depth--;
    pthread_cond_signal(&g_precomp.not_full);
    pthread_mutex_unlock(&g_precomp.mtx);
    return 0;
}

static void* ecdsa_precomp_producer_main(void* arg) {
    (void)arg;
    /* Best-effort pin to CPU 0 so we don't fight the worker
     * (which is pinned to CPU 1 by main.c). Failure is non-fatal —
     * the producer still runs, just possibly contended. */
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    for (;;) {
        /* Wait until there is space in the ring (or shutdown). */
        pthread_mutex_lock(&g_precomp.mtx);
        while (!g_precomp.shutdown && g_precomp.depth >= g_precomp.cap) {
            pthread_cond_wait(&g_precomp.not_full, &g_precomp.mtx);
        }
        if (g_precomp.shutdown) {
            pthread_mutex_unlock(&g_precomp.mtx);
            return NULL;
        }
        pthread_mutex_unlock(&g_precomp.mtx);

        /* Compute the expensive part OUTSIDE the lock so signers can
         * pop while we're working. */
        uint8_t r_be[32], kinv_be[32];
        if (ecdsa_precomp_generate_tuple(r_be, kinv_be) != 0) {
            atomic_fetch_add(&g_precomp.producer_errors, 1);
            /* Avoid a tight failure loop. */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            continue;
        }

        pthread_mutex_lock(&g_precomp.mtx);
        if (g_precomp.shutdown) {
            secure_zero(r_be, sizeof(r_be));
            secure_zero(kinv_be, sizeof(kinv_be));
            pthread_mutex_unlock(&g_precomp.mtx);
            return NULL;
        }
        /* Re-check space (signal could have raced — but only signers
         * pop, so depth can only have decreased while we were
         * generating; still safe.) */
        if (g_precomp.depth < g_precomp.cap) {
            ecdsa_precomp_slot_t* sl = &g_precomp.slots[g_precomp.tail];
            memcpy(sl->r, r_be, 32);
            memcpy(sl->kinv, kinv_be, 32);
            g_precomp.tail = (g_precomp.tail + 1) % g_precomp.cap;
            g_precomp.depth++;
            if (g_precomp.depth > atomic_load(&g_precomp.high_water)) {
                atomic_store(&g_precomp.high_water, g_precomp.depth);
            }
            atomic_fetch_add(&g_precomp.produced, 1);
            pthread_cond_signal(&g_precomp.not_empty);
        }
        secure_zero(r_be, sizeof(r_be));
        secure_zero(kinv_be, sizeof(kinv_be));
        pthread_mutex_unlock(&g_precomp.mtx);
    }
}

int ecdsa_p256_precomp_init(uint32_t pool_cap) {
    if (pool_cap == 0) return -1;
    pthread_once(&g_precomp_once, ecdsa_precomp_global_static_init);
    pthread_mutex_lock(&g_precomp.mtx);
    if (g_precomp.slots) {
        /* Already initialised — idempotent. */
        pthread_mutex_unlock(&g_precomp.mtx);
        return 0;
    }
    g_precomp.slots = (ecdsa_precomp_slot_t*)calloc(pool_cap, sizeof(ecdsa_precomp_slot_t));
    if (!g_precomp.slots) {
        pthread_mutex_unlock(&g_precomp.mtx);
        return -1;
    }
    g_precomp.cap = pool_cap;
    g_precomp.head = 0;
    g_precomp.tail = 0;
    g_precomp.depth = 0;
    g_precomp.shutdown = 0;
    pthread_mutex_unlock(&g_precomp.mtx);

    /* Self-test: generate one tuple synchronously to confirm the math
     * path is sound before we trust the producer thread with TLS
     * traffic. A failure here means we should NOT enable the fast
     * path (leave slots non-NULL but never push anything; sign()
     * still works via fallback). */
    uint8_t test_r[32], test_kinv[32];
    if (ecdsa_precomp_generate_tuple(test_r, test_kinv) != 0) {
        secure_zero(test_r, sizeof(test_r));
        secure_zero(test_kinv, sizeof(test_kinv));
        /* Producer thread not started; pool stays empty forever;
         * sign() will always miss and use inline path. Safe. */
        return -1;
    }
    /* Push the self-test tuple as the first available. */
    pthread_mutex_lock(&g_precomp.mtx);
    memcpy(g_precomp.slots[0].r, test_r, 32);
    memcpy(g_precomp.slots[0].kinv, test_kinv, 32);
    g_precomp.tail = 1;
    g_precomp.depth = 1;
    atomic_store(&g_precomp.high_water, 1);
    atomic_fetch_add(&g_precomp.produced, 1);
    pthread_mutex_unlock(&g_precomp.mtx);
    secure_zero(test_r, sizeof(test_r));
    secure_zero(test_kinv, sizeof(test_kinv));

    if (pthread_create(&g_precomp.producer_tid, NULL,
                       ecdsa_precomp_producer_main, NULL) != 0) {
        /* Pool stays allocated with 1 tuple; sign() will use it once
         * then miss thereafter. Still safe. */
        return -1;
    }
    g_precomp.producer_started = 1;
    return 0;
}

void ecdsa_p256_precomp_shutdown(void) {
    if (!g_precomp.slots || !g_precomp.producer_started) return;
    pthread_mutex_lock(&g_precomp.mtx);
    g_precomp.shutdown = 1;
    pthread_cond_broadcast(&g_precomp.not_full);
    pthread_cond_broadcast(&g_precomp.not_empty);
    pthread_mutex_unlock(&g_precomp.mtx);
    pthread_join(g_precomp.producer_tid, NULL);
    g_precomp.producer_started = 0;
    /* Pool ring itself is intentionally NOT freed — sign() may still
     * be called and must remain safe. It just stops being refilled. */
}

void ecdsa_p256_precomp_get_stats(ecdsa_p256_precomp_stats_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!g_precomp.slots) return;
    /* depth/cap read under lock for consistency; counters are atomic. */
    pthread_mutex_lock(&g_precomp.mtx);
    out->pool_cap = g_precomp.cap;
    out->pool_depth = g_precomp.depth;
    pthread_mutex_unlock(&g_precomp.mtx);
    out->pool_high_water = atomic_load(&g_precomp.high_water);
    out->hits = atomic_load(&g_precomp.hits);
    out->misses = atomic_load(&g_precomp.misses);
    out->produced = atomic_load(&g_precomp.produced);
    out->producer_errors = atomic_load(&g_precomp.producer_errors);
    out->s_zero_fallbacks = atomic_load(&g_precomp.s_zero_fallbacks);
}

int ecdsa_p256_sha256_sign(const uint8_t priv[32],
                           const uint8_t* msg, size_t msg_n,
                           uint8_t out_r[32], uint8_t out_s[32]) {
    if (!priv || (!msg && msg_n) || !out_r || !out_s) return -1;
    u256 d;
    if (scalar_from_be_checked(&d, priv) != 0) return -1;

    uint8_t h1[32], h1oct[32];
    sha256(msg, msg_n, h1);
    bits2octets(h1, h1oct);

    /* Fast path: consume one precomputed (r, kinv) tuple if available.
     * Falls through to inline RFC 6979 path on miss, contention, or
     * the (vanishingly rare) s==0 case. */
    {
        uint8_t r_be[32], kinv_be[32];
        if (ecdsa_precomp_try_pop(r_be, kinv_be) == 0) {
            u256 r, kinv, z, rd, sum, s;
            int ok = (scalar_from_be_checked(&r, r_be) == 0) &&
                     (scalar_from_be_checked(&kinv, kinv_be) == 0);
            if (ok) {
                u256_from_be(&z, h1);
                scalar_reduce_once(&z);
                mod_mul(&rd, &r, &d);
                mod_add(&sum, &z, &rd);
                mod_mul(&s, &kinv, &sum);
                if (!u256_is_zero(&s)) {
                    u256_to_be(&r, out_r);
                    u256_to_be(&s, out_s);
                    secure_zero(&d, sizeof(d));
                    secure_zero(&kinv, sizeof(kinv));
                    secure_zero(&rd, sizeof(rd));
                    secure_zero(&sum, sizeof(sum));
                    secure_zero(&s, sizeof(s));
                    secure_zero(r_be, sizeof(r_be));
                    secure_zero(kinv_be, sizeof(kinv_be));
                    atomic_fetch_add(&g_precomp.hits, 1);
                    return 0;
                }
                atomic_fetch_add(&g_precomp.s_zero_fallbacks, 1);
            }
            secure_zero(&kinv, sizeof(kinv));
            secure_zero(r_be, sizeof(r_be));
            secure_zero(kinv_be, sizeof(kinv_be));
            /* fall through to inline path */
        } else {
            atomic_fetch_add(&g_precomp.misses, 1);
        }
    }

    uint8_t K[32], V[32], kbytes[32];
    memset(K, 0x00, sizeof(K));
    memset(V, 0x01, sizeof(V));
    rfc6979_next(K, V, priv, h1oct, 0x00);
    rfc6979_next(K, V, priv, h1oct, 0x01);

    for (unsigned tries = 0; tries < 1000; tries++) {
        if (rfc6979_generate_k(K, V, kbytes) != 0) break;
        uint8_t xy[64];
        if (p256_scalar_mul_base(kbytes, xy) != 0) continue;
        u256 r;
        u256_from_be(&r, xy);
        scalar_reduce_once(&r);
        if (u256_is_zero(&r)) continue;

        u256 k, kinv, z, rd, sum, s;
        if (scalar_from_be_checked(&k, kbytes) != 0) continue;
        scalar_inv(&kinv, &k);
        u256_from_be(&z, h1);
        scalar_reduce_once(&z);
        mod_mul(&rd, &r, &d);
        mod_add(&sum, &z, &rd);
        mod_mul(&s, &kinv, &sum);
        if (u256_is_zero(&s)) continue;

        u256_to_be(&r, out_r);
        u256_to_be(&s, out_s);
        secure_zero(&d, sizeof(d));
        secure_zero(&k, sizeof(k));
        secure_zero(&kinv, sizeof(kinv));
        secure_zero(kbytes, sizeof(kbytes));
        secure_zero(K, sizeof(K));
        secure_zero(V, sizeof(V));
        return 0;
    }

    secure_zero(&d, sizeof(d));
    secure_zero(kbytes, sizeof(kbytes));
    secure_zero(K, sizeof(K));
    secure_zero(V, sizeof(V));
    return -1;
}

static size_t int_minimal_len(const uint8_t x[32]) {
    size_t i = 0;
    while (i < 31 && x[i] == 0) i++;
    return 32 - i;
}

static int der_write_int(const uint8_t x[32], uint8_t** p, size_t* rem) {
    size_t skip = 32 - int_minimal_len(x);
    const uint8_t* v = x + skip;
    size_t n = 32 - skip;
    uint8_t need_zero = (uint8_t)((v[0] >> 7) & 1u);
    size_t len = n + need_zero;
    if (*rem < 2 + len) return -1;
    *(*p)++ = 0x02;
    *(*p)++ = (uint8_t)len;
    if (need_zero) *(*p)++ = 0x00;
    memcpy(*p, v, n);
    *p += n;
    *rem -= 2 + len;
    return 0;
}

int ecdsa_p256_encode_der(const uint8_t r[32], const uint8_t s[32],
                          uint8_t* out, size_t out_cap) {
    if (!r || !s || !out) return -1;
    size_t r_min = int_minimal_len(r);
    size_t s_min = int_minimal_len(s);
    size_t rn = r_min + ((r[32 - r_min] >> 7) & 1u);
    size_t sn = s_min + ((s[32 - s_min] >> 7) & 1u);
    size_t seq_len = 2 + rn + 2 + sn;
    if (seq_len > 127 || out_cap < 2 + seq_len) return -1;
    uint8_t* p = out;
    size_t rem = out_cap;
    *p++ = 0x30;
    *p++ = (uint8_t)seq_len;
    rem -= 2;
    if (der_write_int(r, &p, &rem) != 0) return -1;
    if (der_write_int(s, &p, &rem) != 0) return -1;
    return (int)(2 + seq_len);
}

int ecdsa_p256_encode_raw64(const uint8_t r[32], const uint8_t s[32],
                            uint8_t out[64]) {
    if (!r || !s || !out) return -1;
    memcpy(out, r, 32);
    memcpy(out + 32, s, 32);
    return 0;
}
