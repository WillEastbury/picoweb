/*
 * Poly1305 (RFC 8439 §2.5) — one-time authenticator.
 *
 * Reference (slow but compact) implementation using a 5x26-bit limb
 * representation for the accumulator. We do not promise this is
 * constant-time on all targets — the additions and multiplications
 * are constant-time, but the modular reduction has a couple of
 * data-dependent carry chains. Good enough for the spike; production
 * code should swap in a tight constant-time implementation.
 *
 * Math:
 *   acc = 0
 *   for each 16-byte block m:
 *     acc = ((acc + (m | 0x01_appended)) * r) mod (2^130 - 5)
 *   tag = (acc + s) mod 2^128
 */

#include "poly1305.h"

#include <string.h>

static inline uint32_t U8TO32_LE(const uint8_t* p) {
    return  (uint32_t)p[0]        | ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void U32TO8_LE(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

void poly1305(const uint8_t key[POLY1305_KEY_LEN],
              const uint8_t* msg, size_t len,
              uint8_t       tag[POLY1305_TAG_LEN]) {
    /* Clamp r per RFC 8439 §2.5.1. */
    uint32_t r0 = (U8TO32_LE(key +  0))      & 0x03ffffff;
    uint32_t r1 = (U8TO32_LE(key +  3) >> 2) & 0x03ffff03;
    uint32_t r2 = (U8TO32_LE(key +  6) >> 4) & 0x03ffc0ff;
    uint32_t r3 = (U8TO32_LE(key +  9) >> 6) & 0x03f03fff;
    uint32_t r4 = (U8TO32_LE(key + 12) >> 8) & 0x000fffff;

    /* Pre-multiply r1..r4 by 5 — used in the reduction step. */
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    /* Accumulator. */
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    while (len > 0) {
        uint8_t block[16];
        size_t take = len < 16 ? len : 16;

        if (take == 16) {
            memcpy(block, msg, 16);
            /* Append the implicit high bit (bit 128). */
            uint32_t hibit = 1u << 24;
            h0 += ((U8TO32_LE(block +  0))     ) & 0x03ffffff;
            h1 += ((U8TO32_LE(block +  3) >> 2)) & 0x03ffffff;
            h2 += ((U8TO32_LE(block +  6) >> 4)) & 0x03ffffff;
            h3 += ((U8TO32_LE(block +  9) >> 6)) & 0x03ffffff;
            h4 += ((U8TO32_LE(block + 12) >> 8)) | hibit;
        } else {
            /* Pad short final block: copy bytes, write 0x01 immediately
             * after, zero the rest. The hibit is folded into the data. */
            memset(block, 0, sizeof(block));
            memcpy(block, msg, take);
            block[take] = 0x01;
            h0 += ((U8TO32_LE(block +  0))     ) & 0x03ffffff;
            h1 += ((U8TO32_LE(block +  3) >> 2)) & 0x03ffffff;
            h2 += ((U8TO32_LE(block +  6) >> 4)) & 0x03ffffff;
            h3 += ((U8TO32_LE(block +  9) >> 6)) & 0x03ffffff;
            h4 += ((U8TO32_LE(block + 12) >> 8));
        }

        /* h = h * r mod (2^130 - 5). 5x5 schoolbook; results in
         * five 64-bit accumulators. */
        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 +
                      (uint64_t)h2 * s3 + (uint64_t)h3 * s2 +
                      (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 +
                      (uint64_t)h2 * s4 + (uint64_t)h3 * s3 +
                      (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 +
                      (uint64_t)h2 * r0 + (uint64_t)h3 * s4 +
                      (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 +
                      (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
                      (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 +
                      (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
                      (uint64_t)h4 * r0;

        /* Carry chain. */
        uint32_t c;
        c  = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffff;
        d1 += c;
        c  = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffff;
        d2 += c;
        c  = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffff;
        d3 += c;
        c  = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffff;
        d4 += c;
        c  = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffff;
        h0 += c * 5;
        c  = h0 >> 26;             h0 &= 0x03ffffff;
        h1 += c;

        msg += take;
        len -= take;
    }

    /* Final reduction: subtract p = 2^130 - 5 if h >= p. */
    uint32_t g0, g1, g2, g3, g4;
    uint32_t mask, c;

    c  = h1 >> 26; h1 &= 0x03ffffff; h2 += c;
    c  = h2 >> 26; h2 &= 0x03ffffff; h3 += c;
    c  = h3 >> 26; h3 &= 0x03ffffff; h4 += c;
    c  = h4 >> 26; h4 &= 0x03ffffff; h0 += c * 5;
    c  = h0 >> 26; h0 &= 0x03ffffff; h1 += c;

    g0 = h0 + 5;
    c  = g0 >> 26; g0 &= 0x03ffffff;
    g1 = h1 + c;
    c  = g1 >> 26; g1 &= 0x03ffffff;
    g2 = h2 + c;
    c  = g2 >> 26; g2 &= 0x03ffffff;
    g3 = h3 + c;
    c  = g3 >> 26; g3 &= 0x03ffffff;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1;   /* 0xffffffff if h >= p, else 0 */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Pack to 4 little-endian 32-bit words. */
    uint32_t f0 = (h0      ) | (h1 << 26);
    uint32_t f1 = (h1 >>  6) | (h2 << 20);
    uint32_t f2 = (h2 >> 12) | (h3 << 14);
    uint32_t f3 = (h3 >> 18) | (h4 <<  8);

    /* Add s. */
    uint64_t f;
    f = (uint64_t)f0 + U8TO32_LE(key + 16);
    f0 = (uint32_t)f;
    f = (uint64_t)f1 + U8TO32_LE(key + 20) + (f >> 32);
    f1 = (uint32_t)f;
    f = (uint64_t)f2 + U8TO32_LE(key + 24) + (f >> 32);
    f2 = (uint32_t)f;
    f = (uint64_t)f3 + U8TO32_LE(key + 28) + (f >> 32);
    f3 = (uint32_t)f;

    U32TO8_LE(tag +  0, f0);
    U32TO8_LE(tag +  4, f1);
    U32TO8_LE(tag +  8, f2);
    U32TO8_LE(tag + 12, f3);
}
