/*
 * SHA-256 compression — ARMv8-A FEAT_SHA256 implementation.
 *
 * Uses the FEAT_SHA256 instructions (AArch64 base):
 *
 *   sha256h   — SHA-256 hash update part 1 (rounds, low word)
 *   sha256h2  — SHA-256 hash update part 2 (rounds, high word)
 *   sha256su0 — schedule update part 1 (sigma0 + add)
 *   sha256su1 — schedule update part 2 (sigma1 + previous + new)
 *
 * Reference: Arm Architecture Reference Manual for A-profile,
 * sections C2.5 ("Cryptographic Extension") and C7.2.SHA256H.
 *
 * State register layout: the FIPS abstract state a..h is split into
 * two 128-bit Q registers as 4-lane uint32:
 *
 *   ABEF = { D, C, B, A }   (low→high inside the vector)
 *   CDGH = { H, G, F, E }
 *
 * (I.e. per the Arm ARM, sha256h/sha256h2 take the top half in d0
 *  and the bottom half in d1 and write back two 4-lane vectors.)
 *
 * The TU is compiled with `target("+crypto")` so the intrinsics are
 * available without forcing the whole build to require FEAT_SHA256.
 * Runtime dispatch in sha256.c only points here on CPUs that
 * advertise HWCAP_SHA2.
 */

#include "sha256.h"

#if defined(__aarch64__)

#pragma GCC push_options
#pragma GCC target("+crypto")

#include <arm_neon.h>

/* SHA-256 round constants K[0..63] (FIPS 180-4 §4.2.2). */
static const uint32_t K[64] __attribute__((aligned(16))) = {
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

void sha256_compress_armv8(uint32_t state[8],
                           const uint8_t* blocks, size_t nblocks) {
    /* Load running state. ARM ARM convention: ABEF holds {a,b,c,d}
     * as a four-lane vector (lane 0 = a), CDGH holds {e,f,g,h}.
     * (Names in the docs vary; this matches GCC's intrinsic prototype
     *  where vsha256hq_u32 takes (hash_abcd, hash_efgh, wk).) */
    uint32x4_t abcd = vld1q_u32(&state[0]);
    uint32x4_t efgh = vld1q_u32(&state[4]);

    while (nblocks--) {
        uint32x4_t s_abcd = abcd;
        uint32x4_t s_efgh = efgh;

        /* Load and byte-swap the 16-word message schedule (network
         * byte order → host). One vrev32q per 16-byte chunk. */
        uint32x4_t w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks + 0)));
        uint32x4_t w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks + 16)));
        uint32x4_t w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks + 32)));
        uint32x4_t w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks + 48)));

        uint32x4_t wk;     /* W + K for the current 4-round group */
        uint32x4_t tmp;    /* spill for the in-place hash update    */

        /* Macro: one 4-round group given W (already loaded) and K
         * round-base. sha256h returns a new abcd; sha256h2 returns a
         * new efgh that USES THE OLD abcd as one of its inputs, so
         * we must save abcd first. */
        #define SHA256_ROUND4(W, KBASE)                                  \
            do {                                                         \
                wk  = vaddq_u32((W), vld1q_u32(&K[(KBASE)]));            \
                tmp = abcd;                                              \
                abcd = vsha256hq_u32 (abcd, efgh, wk);                   \
                efgh = vsha256h2q_u32(efgh, tmp,  wk);                   \
            } while (0)

        /* Rounds 0–15: schedule words come straight from the block.   */
        SHA256_ROUND4(w0,  0);
        SHA256_ROUND4(w1,  4);
        SHA256_ROUND4(w2,  8);
        SHA256_ROUND4(w3, 12);

        /* Rounds 16–63: 12 4-round groups with on-the-fly schedule
         * expansion. Per Arm ARM:
         *   W_new = sha256su1(sha256su0(W[i-16], W[i-12]),
         *                     W[i-8], W[i-4])
         * In our rolling-4 register window (w0..w3) on entry to each
         * iteration we have W[i-16..i-13] in w0, ..., W[i-4..i-1]
         * in w3. Compute next W into a fresh vector then rotate. */
        for (int kbase = 16; kbase < 64; kbase += 4) {
            uint32x4_t w_new = vsha256su0q_u32(w0, w1);
            w_new = vsha256su1q_u32(w_new, w2, w3);

            SHA256_ROUND4(w_new, kbase);

            w0 = w1;
            w1 = w2;
            w2 = w3;
            w3 = w_new;
        }
        #undef SHA256_ROUND4

        /* Add the running state. */
        abcd = vaddq_u32(abcd, s_abcd);
        efgh = vaddq_u32(efgh, s_efgh);

        blocks += 64;
    }

    vst1q_u32(&state[0], abcd);
    vst1q_u32(&state[4], efgh);
}

#pragma GCC pop_options

#else  /* !__aarch64__ */

/* Stub for non-aarch64 builds — never called (gated in sha256.c
 * by #if defined(__aarch64__)) but keeps the symbol referenceable
 * if some build accidentally pulls this TU in. */
void sha256_compress_armv8(uint32_t state[8],
                           const uint8_t* blocks, size_t nblocks) {
    (void)state; (void)blocks; (void)nblocks;
}

#endif
