#ifndef METAL_SIMD_H
#define METAL_SIMD_H

/* Inline SIMD primitives for x86-64 (SSE2) and aarch64 (NEON), with
 * scalar fallback. SSE2 and NEON are baseline on those targets so no
 * compile-time flag is needed beyond a sufficiently modern compiler.
 *
 * Two primitives are exposed:
 *   metal_eq_n(a, b, len)     — byte-equality of two ranges.
 *   metal_lower_simd(buf, n)  — in-place ASCII A..Z → a..z.
 *
 * Used on the request hot path:
 *   - host & path memcmp inside flat_lookup
 *   - lowercasing the Host header in http_parse
 *
 * Detected variants are reported by metal_simd_describe().
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if defined(__SSE2__) || defined(__x86_64__) || defined(_M_X64)
#  include <emmintrin.h>
#  define METAL_SIMD_X64_SSE2 1
#endif

#if defined(__aarch64__) || defined(__ARM_NEON) || defined(__ARM_NEON__)
#  include <arm_neon.h>
#  define METAL_SIMD_AARCH64_NEON 1
#endif

static inline const char* metal_simd_describe(void) {
#if defined(METAL_SIMD_X64_SSE2)
    return "x86-64 SSE2";
#elif defined(METAL_SIMD_AARCH64_NEON)
    return "aarch64 NEON";
#else
    return "scalar";
#endif
}

/* Equality compare two byte ranges of length len. Returns true if equal.
 * For len < 16 falls through to glibc memcmp (which is itself dispatched
 * to fast paths on most libc builds). */
static inline bool metal_eq_n(const void* a_, const void* b_, size_t len) {
    const unsigned char* a = (const unsigned char*)a_;
    const unsigned char* b = (const unsigned char*)b_;

#if defined(METAL_SIMD_X64_SSE2)
    while (len >= 16) {
        __m128i va = _mm_loadu_si128((const __m128i*)a);
        __m128i vb = _mm_loadu_si128((const __m128i*)b);
        __m128i eq = _mm_cmpeq_epi8(va, vb);
        if ((unsigned)_mm_movemask_epi8(eq) != 0xffffu) return false;
        a += 16; b += 16; len -= 16;
    }
#elif defined(METAL_SIMD_AARCH64_NEON)
    while (len >= 16) {
        uint8x16_t va = vld1q_u8(a);
        uint8x16_t vb = vld1q_u8(b);
        uint8x16_t cmp = vceqq_u8(va, vb);
        /* All-equal iff min lane is 0xff. */
        if (vminvq_u8(cmp) != 0xff) return false;
        a += 16; b += 16; len -= 16;
    }
#endif

    /* Tail. memcmp on small sizes is well optimised in glibc. */
    return len == 0 || memcmp(a, b, len) == 0;
}

/* In-place ASCII A..Z → a..z on a byte range. High-bit and non-letter
 * bytes are left untouched. Bounds checking is the caller's job. */
static inline void metal_lower_simd(char* buf, size_t len) {
    unsigned char* p = (unsigned char*)buf;

#if defined(METAL_SIMD_X64_SSE2)
    /* Signed cmpgt; high-bit (negative) bytes correctly fail both
     * comparisons so they're left alone. */
    const __m128i Aminus1 = _mm_set1_epi8((char)('A' - 1));
    const __m128i Z       = _mm_set1_epi8((char)'Z');
    const __m128i ones    = _mm_set1_epi8((char)0xff);
    const __m128i cb      = _mm_set1_epi8((char)0x20);
    while (len >= 16) {
        __m128i v       = _mm_loadu_si128((const __m128i*)p);
        __m128i gt_a    = _mm_cmpgt_epi8(v, Aminus1);          /* v >= 'A' */
        __m128i gt_z    = _mm_cmpgt_epi8(v, Z);                /* v > 'Z'  */
        __m128i not_gtz = _mm_xor_si128(gt_z, ones);           /* v <= 'Z' */
        __m128i mask    = _mm_and_si128(gt_a, not_gtz);
        __m128i add     = _mm_and_si128(mask, cb);
        v = _mm_add_epi8(v, add);
        _mm_storeu_si128((__m128i*)p, v);
        p += 16; len -= 16;
    }
#elif defined(METAL_SIMD_AARCH64_NEON)
    const uint8x16_t Aminus1 = vdupq_n_u8('A' - 1);
    const uint8x16_t Zplus1  = vdupq_n_u8('Z' + 1);
    const uint8x16_t cb      = vdupq_n_u8(0x20);
    while (len >= 16) {
        uint8x16_t v    = vld1q_u8(p);
        uint8x16_t gt_a = vcgtq_u8(v, Aminus1);                /* unsigned > */
        uint8x16_t lt_z = vcltq_u8(v, Zplus1);
        uint8x16_t mask = vandq_u8(gt_a, lt_z);
        uint8x16_t add  = vandq_u8(mask, cb);
        v = vaddq_u8(v, add);
        vst1q_u8(p, v);
        p += 16; len -= 16;
    }
#endif

    /* Scalar tail. */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = p[i];
        if (c >= 'A' && c <= 'Z') p[i] = (unsigned char)(c | 0x20);
    }
}

#endif /* METAL_SIMD_H */
