#include "ecdsa.h"

#include <string.h>

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

int ecdsa_p256_sha256_sign(const uint8_t priv[32],
                           const uint8_t* msg, size_t msg_n,
                           uint8_t out_r[32], uint8_t out_s[32]) {
    if (!priv || (!msg && msg_n) || !out_r || !out_s) return -1;
    u256 d;
    if (scalar_from_be_checked(&d, priv) != 0) return -1;

    uint8_t h1[32], h1oct[32];
    sha256(msg, msg_n, h1);
    bits2octets(h1, h1oct);

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
