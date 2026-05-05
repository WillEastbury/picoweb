/*
 * SHA-256 (FIPS 180-4) — pure C reference implementation.
 *
 * The compression function `sha256_compress` is the core; everything
 * else is buffering and length encoding. Verified against the four
 * well-known short-message NIST CAVP test vectors and against the
 * RFC 6234 sample vectors in tests/test_sha256.c.
 *
 * Memory:
 *   - All state is on the caller-provided sha256_ctx (no allocations).
 *   - The compression function copies the message block into 64
 *     32-bit words on the stack (256 bytes) plus the 8 working
 *     registers a..h.
 */

#include "sha256.h"

#include <string.h>

/* FIPS 180-4 §4.2.2 — first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes (2..311). */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static inline uint32_t big_sigma0(uint32_t x) {
    return rotr32(x, 2)  ^ rotr32(x, 13) ^ rotr32(x, 22);
}
static inline uint32_t big_sigma1(uint32_t x) {
    return rotr32(x, 6)  ^ rotr32(x, 11) ^ rotr32(x, 25);
}
static inline uint32_t small_sigma0(uint32_t x) {
    return rotr32(x, 7)  ^ rotr32(x, 18) ^ (x >> 3);
}
static inline uint32_t small_sigma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t load_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = load_be32(block + i * 4);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = small_sigma1(w[i-2]) + w[i-7] + small_sigma0(w[i-15]) + w[i-16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + big_sigma1(e) + Ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = big_sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* FIPS 180-4 §5.3.3 — initial hash values for SHA-256:
 * first 32 bits of the fractional parts of the square roots of the
 * first 8 primes. */
void sha256_init(sha256_ctx* c) {
    c->state[0] = 0x6a09e667;
    c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372;
    c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f;
    c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab;
    c->state[7] = 0x5be0cd19;
    c->bitlen = 0;
    c->buf_len = 0;
}

void sha256_update(sha256_ctx* c, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    c->bitlen += (uint64_t)len * 8u;

    /* Drain the buffer first if there's a partial block. */
    if (c->buf_len) {
        size_t need = SHA256_BLOCK_LEN - c->buf_len;
        if (len < need) {
            memcpy(c->buf + c->buf_len, p, len);
            c->buf_len += len;
            return;
        }
        memcpy(c->buf + c->buf_len, p, need);
        sha256_compress(c->state, c->buf);
        c->buf_len = 0;
        p   += need;
        len -= need;
    }

    /* Consume full blocks straight from the caller's buffer. */
    while (len >= SHA256_BLOCK_LEN) {
        sha256_compress(c->state, p);
        p   += SHA256_BLOCK_LEN;
        len -= SHA256_BLOCK_LEN;
    }

    /* Stash the remainder. */
    if (len) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }
}

void sha256_final(sha256_ctx* c, uint8_t out[SHA256_DIGEST_LEN]) {
    /* Padding: append 0x80 then zeros until 56 bytes mod 64, then
     * the 64-bit big-endian message length in bits. */
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > 56) {
        memset(c->buf + c->buf_len, 0, SHA256_BLOCK_LEN - c->buf_len);
        sha256_compress(c->state, c->buf);
        c->buf_len = 0;
    }
    memset(c->buf + c->buf_len, 0, 56 - c->buf_len);
    /* Big-endian 64-bit length. */
    for (int i = 0; i < 8; i++) {
        c->buf[56 + i] = (uint8_t)(c->bitlen >> (56 - i * 8));
    }
    sha256_compress(c->state, c->buf);

    for (int i = 0; i < 8; i++) {
        store_be32(out + i * 4, c->state[i]);
    }

    /* Wipe sensitive state. */
    memset(c, 0, sizeof(*c));
}

void sha256(const void* data, size_t len, uint8_t out[SHA256_DIGEST_LEN]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}
