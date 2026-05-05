/*
 * ChaCha20 — SSE2 4-way parallel implementation.
 *
 * Strategy: maintain 16 SSE2 registers, each holding one ChaCha20
 * state word from 4 independent blocks (counters c, c+1, c+2, c+3).
 * One quarter-round operates on 4 blocks at once via SIMD adds, XORs
 * and rotates. After 20 rounds we add the original state, transpose
 * back to 4 contiguous 64-byte blocks, and XOR with the input.
 *
 * SSE2 baseline: every x86_64 CPU has SSE2; no runtime check needed
 * beyond "we're on x86". We don't use SSSE3 pshufb here (rotate-by-8
 * and -by-16 use the slightly slower add+shr+or pattern) — staying
 * SSE2-only keeps the dispatch matrix trivial.
 *
 * Falls through to the scalar path for tail bytes < 256 (i.e. less
 * than 4 full blocks). For TLS 1.3 records up to 16 KiB this is the
 * common case; the tail handles the small final fragment.
 *
 * Verified against the scalar implementation on every byte length
 * from 0..1024 in test_crypto.c::test_chacha20_dispatch.
 */

#include "chacha20.h"

#if defined(__x86_64__) || defined(__i386__)

#pragma GCC push_options
#pragma GCC target("sse2")

#include <emmintrin.h>
#include <string.h>

static inline __m128i rotl_epi32(__m128i x, int n) {
    /* SSE2 has no variable rotate; emulate with shift+shift+or. */
    return _mm_or_si128(_mm_slli_epi32(x, n), _mm_srli_epi32(x, 32 - n));
}

#define QR4(a,b,c,d) do {                          \
    a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = rotl_epi32(d, 16); \
    c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = rotl_epi32(b, 12); \
    a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = rotl_epi32(d,  8); \
    c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = rotl_epi32(b,  7); \
} while (0)

static inline uint32_t load_le32(const uint8_t* p) {
    return  (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Compute four ChaCha20 blocks for counters {c0, c0+1, c0+2, c0+3}
 * and write the 4*64 = 256 bytes of keystream to ks. */
static void chacha20_4blocks(const uint8_t key[32],
                             uint32_t c0,
                             const uint8_t nonce[12],
                             uint8_t ks[256]) {
    /* Initial state words s0..s15 (host endianness; we store back
     * little-endian via the implicit memory layout when we add the
     * original state and store). */
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e;
    s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = load_le32(key + i * 4);
    s[12] = c0;
    s[13] = load_le32(nonce + 0);
    s[14] = load_le32(nonce + 4);
    s[15] = load_le32(nonce + 8);

    /* Each xmm register holds one state word across the 4 lanes.
     * Lane 0 = block c0, lane 1 = block c0+1, ... so lane j of v12
     * is c0+j. */
    __m128i v[16];
    for (int i = 0; i < 16; i++) v[i] = _mm_set1_epi32((int)s[i]);
    v[12] = _mm_set_epi32((int)(s[12] + 3), (int)(s[12] + 2),
                          (int)(s[12] + 1), (int)(s[12] + 0));

    __m128i x[16];
    for (int i = 0; i < 16; i++) x[i] = v[i];

    for (int r = 0; r < 10; r++) {
        /* Column rounds */
        QR4(x[0], x[4], x[ 8], x[12]);
        QR4(x[1], x[5], x[ 9], x[13]);
        QR4(x[2], x[6], x[10], x[14]);
        QR4(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QR4(x[0], x[5], x[10], x[15]);
        QR4(x[1], x[6], x[11], x[12]);
        QR4(x[2], x[7], x[ 8], x[13]);
        QR4(x[3], x[4], x[ 9], x[14]);
    }

    /* Add the original state word-by-word (re-injects the counter
     * lane offsets via v[12] which already had +0..+3 baked in). */
    for (int i = 0; i < 16; i++) x[i] = _mm_add_epi32(x[i], v[i]);

    /* Now x[i] holds 4 lane values for state word i across blocks
     * 0..3. Transpose so that ks[block_j * 64 + word_i * 4] holds
     * lane j of x[i] in little-endian.
     *
     * We process 4 words at a time (one row of 4 SIMD regs) and
     * use the standard 4x4 32-bit transpose:
     *   _MM_TRANSPOSE4_PS-equivalent built from punpckl/hi.
     */
    for (int row = 0; row < 4; row++) {
        __m128i a = x[row * 4 + 0];
        __m128i b = x[row * 4 + 1];
        __m128i c = x[row * 4 + 2];
        __m128i d = x[row * 4 + 3];

        /* 4x4 transpose: a,b,c,d are rows; we produce columns. */
        __m128i ab_lo = _mm_unpacklo_epi32(a, b);   /* a0 b0 a1 b1 */
        __m128i ab_hi = _mm_unpackhi_epi32(a, b);   /* a2 b2 a3 b3 */
        __m128i cd_lo = _mm_unpacklo_epi32(c, d);   /* c0 d0 c1 d1 */
        __m128i cd_hi = _mm_unpackhi_epi32(c, d);   /* c2 d2 c3 d3 */

        __m128i col0 = _mm_unpacklo_epi64(ab_lo, cd_lo);  /* a0 b0 c0 d0 */
        __m128i col1 = _mm_unpackhi_epi64(ab_lo, cd_lo);  /* a1 b1 c1 d1 */
        __m128i col2 = _mm_unpacklo_epi64(ab_hi, cd_hi);  /* a2 b2 c2 d2 */
        __m128i col3 = _mm_unpackhi_epi64(ab_hi, cd_hi);  /* a3 b3 c3 d3 */

        /* col_j becomes the row-th 16-byte chunk of block j. */
        _mm_storeu_si128((__m128i*)(ks + 0 * 64 + row * 16), col0);
        _mm_storeu_si128((__m128i*)(ks + 1 * 64 + row * 16), col1);
        _mm_storeu_si128((__m128i*)(ks + 2 * 64 + row * 16), col2);
        _mm_storeu_si128((__m128i*)(ks + 3 * 64 + row * 16), col3);
    }
}

void chacha20_xor_sse2(const uint8_t key[32],
                       uint32_t counter,
                       const uint8_t nonce[12],
                       const uint8_t* in, uint8_t* out, size_t len) {
    /* Process full 4-block (256-byte) chunks via SIMD. */
    while (len >= 256) {
        uint8_t ks[256] __attribute__((aligned(16)));
        chacha20_4blocks(key, counter, nonce, ks);
        /* XOR the 256-byte keystream against in -> out, 16 bytes at
         * a time. We support unaligned in/out. */
        for (size_t i = 0; i < 256; i += 16) {
            __m128i d = _mm_loadu_si128((const __m128i*)(in + i));
            __m128i k = _mm_load_si128((const __m128i*)(ks + i));
            _mm_storeu_si128((__m128i*)(out + i), _mm_xor_si128(d, k));
        }
        in += 256; out += 256; len -= 256;
        counter += 4;

        /* Wipe ks before it leaves cache. SSE2 has no constant-time
         * memset; use a scalar zero-out. */
        for (size_t i = 0; i < 256; i += 16) {
            _mm_store_si128((__m128i*)(ks + i), _mm_setzero_si128());
        }
    }

    /* Tail: 0..255 bytes. Defer to the scalar path for the trailing
     * piece. The scalar impl handles partial blocks. */
    if (len > 0) {
        chacha20_xor_scalar(key, counter, nonce, in, out, len);
    }
}

#pragma GCC pop_options

#endif /* x86 */
