/*
 * SHA-256 compression — Intel SHA-NI (x86_64) implementation.
 *
 * Uses the SHA-NI ISA extension (CPUID leaf 7, EBX bit 29):
 *
 *   sha256rnds2  — performs two rounds of SHA-256
 *   sha256msg1   — message schedule helper part 1
 *   sha256msg2   — message schedule helper part 2
 *
 * Reference: Intel "Intrinsics Guide" + "Intel SHA Extensions Software
 * Developer's Manual" (323940, 2013).
 *
 * Registers carry SHA state in two 128-bit XMM registers:
 *
 *   STATE0 = { F, E, B, A }   (high to low; sha256rnds2 input layout)
 *   STATE1 = { H, G, D, C }
 *
 * On entry from / exit to the FIPS layout (a..h in state[0..7]) we
 * shuffle to/from this packed form.
 *
 * This entire TU is compiled with `target("sse4.1,sha")` so the
 * intrinsics are available without forcing the whole build to
 * require SHA-NI. Runtime dispatch in sha256.c only points here on
 * CPUs that advertise the SHA bit.
 */

#include "sha256.h"

#if defined(__x86_64__) || defined(__i386__)

/* Make the intrinsics available even when the wider build target is
 * baseline x86_64. We don't add target-attribute on the function
 * itself (some older clangs choke on it combined with
 * target_clones); instead we rely on the include + CPUID gate. */
#pragma GCC push_options
#pragma GCC target("sse4.1,sha")

#include <immintrin.h>

/* SHA-256 round constants, packed as 4-lane 32-bit groups in the
 * order sha256rnds2 expects (high-to-low: K[i+3], K[i+2], K[i+1], K[i]). */
static const uint32_t K_packed[64] __attribute__((aligned(16))) = {
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

/* Byte-swap shuffle mask: convert big-endian message bytes to host
 * little-endian words while loaded as 16 bytes.
 *
 *   in : b3 b2 b1 b0  b7 b6 b5 b4 ...   (memory order)
 *   out: b0 b1 b2 b3  b4 b5 b6 b7 ...   (so when read as u32 LE
 *        you get the original 32-bit big-endian word).
 *
 * pshufb selects byte i of dst from byte mask[i] of src. */
static const uint8_t bswap_mask[16] __attribute__((aligned(16))) = {
    3,2,1,0,  7,6,5,4,  11,10,9,8,  15,14,13,12
};

void sha256_compress_shani(uint32_t state[8], const uint8_t* blocks, size_t nblocks) {
    /* Reorder FIPS state[a..h] into the packed form sha256rnds2
     * expects. Comments use Intel's high-to-low notation for register
     * lane contents (so "DCBA" = lane3 holds D, lane0 holds A; this
     * is what _mm_loadu_si128 produces when reading {a,b,c,d} from
     * memory). The pattern matches the Linux kernel SHA-NI asm at
     * arch/x86/crypto/sha256_ni_asm.S. */
    __m128i state0, state1;
    __m128i tmp;

    tmp    = _mm_loadu_si128((const __m128i*)&state[0]);   /* DCBA */
    state1 = _mm_loadu_si128((const __m128i*)&state[4]);   /* HGFE */

    tmp    = _mm_shuffle_epi32(tmp,    0xB1);              /* CDAB */
    state1 = _mm_shuffle_epi32(state1, 0x1B);              /* EFGH */
    state0 = _mm_alignr_epi8(tmp, state1, 8);              /* ABEF */
    state1 = _mm_blend_epi16(state1, tmp, 0xF0);           /* CDGH */

    const __m128i mask = _mm_load_si128((const __m128i*)bswap_mask);

    for (size_t b = 0; b < nblocks; b++) {
        const uint8_t* blk = blocks + b * SHA256_BLOCK_LEN;

        __m128i abef_save = state0;
        __m128i cdgh_save = state1;

        /* Load 4 message-schedule quads (16 words) and byte-swap. */
        __m128i msg0 = _mm_loadu_si128((const __m128i*)(blk +  0));
        __m128i msg1 = _mm_loadu_si128((const __m128i*)(blk + 16));
        __m128i msg2 = _mm_loadu_si128((const __m128i*)(blk + 32));
        __m128i msg3 = _mm_loadu_si128((const __m128i*)(blk + 48));
        msg0 = _mm_shuffle_epi8(msg0, mask);
        msg1 = _mm_shuffle_epi8(msg1, mask);
        msg2 = _mm_shuffle_epi8(msg2, mask);
        msg3 = _mm_shuffle_epi8(msg3, mask);

        __m128i msg, tmsg;

        /* Rounds 0-3 */
        msg  = _mm_add_epi32(msg0, _mm_load_si128((const __m128i*)&K_packed[0]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        /* Rounds 4-7 */
        msg  = _mm_add_epi32(msg1, _mm_load_si128((const __m128i*)&K_packed[4]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        /* Rounds 8-11 */
        msg  = _mm_add_epi32(msg2, _mm_load_si128((const __m128i*)&K_packed[8]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        /* Rounds 12-15 */
        msg  = _mm_add_epi32(msg3, _mm_load_si128((const __m128i*)&K_packed[12]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmsg);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        /* Rounds 16-19 */
        msg  = _mm_add_epi32(msg0, _mm_load_si128((const __m128i*)&K_packed[16]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmsg);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        /* Rounds 20-23 */
        msg  = _mm_add_epi32(msg1, _mm_load_si128((const __m128i*)&K_packed[20]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmsg);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        /* Rounds 24-27 */
        msg  = _mm_add_epi32(msg2, _mm_load_si128((const __m128i*)&K_packed[24]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmsg);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        /* Rounds 28-31 */
        msg  = _mm_add_epi32(msg3, _mm_load_si128((const __m128i*)&K_packed[28]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmsg);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        /* Rounds 32-35 */
        msg  = _mm_add_epi32(msg0, _mm_load_si128((const __m128i*)&K_packed[32]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmsg);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        /* Rounds 36-39 */
        msg  = _mm_add_epi32(msg1, _mm_load_si128((const __m128i*)&K_packed[36]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmsg);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        /* Rounds 40-43 */
        msg  = _mm_add_epi32(msg2, _mm_load_si128((const __m128i*)&K_packed[40]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmsg);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        /* Rounds 44-47 */
        msg  = _mm_add_epi32(msg3, _mm_load_si128((const __m128i*)&K_packed[44]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmsg);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        /* Rounds 48-51 */
        msg  = _mm_add_epi32(msg0, _mm_load_si128((const __m128i*)&K_packed[48]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmsg);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        /* Rounds 52-55 */
        msg  = _mm_add_epi32(msg1, _mm_load_si128((const __m128i*)&K_packed[52]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmsg);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        /* Rounds 56-59 */
        msg  = _mm_add_epi32(msg2, _mm_load_si128((const __m128i*)&K_packed[56]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmsg = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmsg);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        /* Rounds 60-63 */
        msg  = _mm_add_epi32(msg3, _mm_load_si128((const __m128i*)&K_packed[60]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg  = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        /* Add saved state. */
        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);
    }

    /* Reverse the entry shuffle: state0={ABEF}, state1={CDGH} packed
     * back to a..h memory order. Use punpck to interleave 64-bit
     * halves cleanly.
     *
     *   state0 lanes (lo->hi): [F,E,B,A]
     *   state1 lanes (lo->hi): [H,G,D,C]
     *   pshufd 0x1B reverses lanes:
     *     ta (lo->hi): [A,B,E,F]
     *     tb (lo->hi): [C,D,G,H]
     *   unpacklo_epi64(ta,tb) = lo64 of each = [A,B,C,D]   -> state[0..3]
     *   unpackhi_epi64(ta,tb) = hi64 of each = [E,F,G,H]   -> state[4..7]
     */
    __m128i ta = _mm_shuffle_epi32(state0, 0x1B);
    __m128i tb = _mm_shuffle_epi32(state1, 0x1B);
    __m128i out0 = _mm_unpacklo_epi64(ta, tb);
    __m128i out1 = _mm_unpackhi_epi64(ta, tb);
    _mm_storeu_si128((__m128i*)&state[0], out0);
    _mm_storeu_si128((__m128i*)&state[4], out1);
}

#pragma GCC pop_options

#endif /* x86 */
