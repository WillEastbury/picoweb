/*
 * AES-128 (FIPS-197) byte-oriented reference implementation.
 *
 * Used by:
 *   - userspace/crypto/aes_gcm.c : GCTR + GHASH-h derivation
 *   - userspace/quic/hp.c         : header-protection sample-encrypt
 *
 * Not constant-time on its own. ARMv8 AES intrinsics path will be
 * added in a follow-up; the dispatch will live in this same file
 * behind aes128_init/aes128_encrypt_block.
 */
#include "aes.h"

#include <string.h>

/* Forward S-box (FIPS-197 §5.1.1, Figure 7). */
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Round constants (FIPS-197 §5.2). Only Rcon[1..10] are used for
 * AES-128 key expansion. */
static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint32_t rd32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/* Reserved for the upcoming ARMv8 AES intrinsics path. */
__attribute__((unused))
static void wr32be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}

static uint32_t sub_word(uint32_t w) {
    return  ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) |
            ((uint32_t)SBOX[(w >> 16) & 0xff] << 16) |
            ((uint32_t)SBOX[(w >>  8) & 0xff] <<  8) |
             (uint32_t)SBOX[ w        & 0xff];
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/* Multiply by x in GF(2^8) with the AES reduction polynomial 0x1b. */
static uint8_t xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
}

void aes128_init(aes128_ctx_t* ctx, const uint8_t key[AES128_KEY_LEN]) {
    /* First 4 words = key. */
    for (int i = 0; i < 4; i++) {
        ctx->rk[i] = rd32be(key + 4 * i);
    }
    /* Generate remaining 40 words. */
    for (int i = 4; i < (int)AES128_RK_WORDS; i++) {
        uint32_t t = ctx->rk[i - 1];
        if ((i & 3) == 0) {
            t = sub_word(rot_word(t)) ^ ((uint32_t)RCON[i / 4] << 24);
        }
        ctx->rk[i] = ctx->rk[i - 4] ^ t;
    }
}

void aes128_encrypt_block(const aes128_ctx_t* ctx,
                          const uint8_t in[AES128_BLOCK_LEN],
                          uint8_t out[AES128_BLOCK_LEN]) {
    /* State as 16 bytes column-major: state[c*4+r] is row r, col c. */
    uint8_t s[16];
    memcpy(s, in, 16);

    /* Initial AddRoundKey with rk[0..3]. */
    for (int c = 0; c < 4; c++) {
        uint32_t k = ctx->rk[c];
        s[c*4 + 0] ^= (uint8_t)(k >> 24);
        s[c*4 + 1] ^= (uint8_t)(k >> 16);
        s[c*4 + 2] ^= (uint8_t)(k >>  8);
        s[c*4 + 3] ^= (uint8_t)(k);
    }

    for (unsigned round = 1; round <= AES128_NR; round++) {
        /* SubBytes. */
        for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];

        /* ShiftRows: row r is rotated left by r bytes. State is
         * column-major, so row r byte at column c is s[c*4+r]. */
        uint8_t t;
        /* row 1: rotate left 1 */
        t = s[0*4+1];
        s[0*4+1] = s[1*4+1]; s[1*4+1] = s[2*4+1];
        s[2*4+1] = s[3*4+1]; s[3*4+1] = t;
        /* row 2: rotate left 2 (swap c0<->c2, c1<->c3) */
        t = s[0*4+2]; s[0*4+2] = s[2*4+2]; s[2*4+2] = t;
        t = s[1*4+2]; s[1*4+2] = s[3*4+2]; s[3*4+2] = t;
        /* row 3: rotate left 3 == rotate right 1 */
        t = s[3*4+3];
        s[3*4+3] = s[2*4+3]; s[2*4+3] = s[1*4+3];
        s[1*4+3] = s[0*4+3]; s[0*4+3] = t;

        /* MixColumns (skip on final round). */
        if (round != AES128_NR) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[c*4+0], a1 = s[c*4+1], a2 = s[c*4+2], a3 = s[c*4+3];
                uint8_t x0 = xtime(a0), x1 = xtime(a1),
                        x2 = xtime(a2), x3 = xtime(a3);
                s[c*4+0] = x0 ^ a3 ^ a2 ^ x1 ^ a1;       /* 2a0 + 3a1 + a2 + a3 */
                s[c*4+1] = x1 ^ a0 ^ a3 ^ x2 ^ a2;       /* a0 + 2a1 + 3a2 + a3 */
                s[c*4+2] = x2 ^ a1 ^ a0 ^ x3 ^ a3;       /* a0 + a1 + 2a2 + 3a3 */
                s[c*4+3] = x3 ^ a2 ^ a1 ^ x0 ^ a0;       /* 3a0 + a1 + a2 + 2a3 */
            }
        }

        /* AddRoundKey for this round. */
        const uint32_t* rk = &ctx->rk[round * 4];
        for (int c = 0; c < 4; c++) {
            uint32_t k = rk[c];
            s[c*4 + 0] ^= (uint8_t)(k >> 24);
            s[c*4 + 1] ^= (uint8_t)(k >> 16);
            s[c*4 + 2] ^= (uint8_t)(k >>  8);
            s[c*4 + 3] ^= (uint8_t)(k);
        }
    }

    memcpy(out, s, 16);
}
