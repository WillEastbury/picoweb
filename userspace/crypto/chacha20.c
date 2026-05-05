/*
 * ChaCha20 (RFC 8439 §2.4) — pure C reference.
 *
 * The 64-byte initial state is laid out as 16 32-bit little-endian words:
 *   [ "expa" "nd 3" "2-by" "te k" ]    (constants)
 *   [    key[0..15]              ]
 *   [    key[16..31]             ]
 *   [ counter | nonce[0..11]     ]
 *
 * One quarter-round on (a,b,c,d):
 *   a += b; d ^= a; d <<<= 16
 *   c += d; b ^= c; b <<<= 12
 *   a += b; d ^= a; d <<<=  8
 *   c += d; b ^= c; b <<<=  7
 *
 * Twenty rounds = 10x (column round + diagonal round). After twenty
 * rounds we add the original state back and serialise as little-endian
 * — that's the keystream block.
 */

#include "chacha20.h"

#include <string.h>

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32u - n));
}

static inline uint32_t load_le32(const uint8_t* p) {
    return  (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7); \
} while (0)

void chacha20_block(const uint8_t key[CHACHA20_KEY_LEN],
                    uint32_t      counter,
                    const uint8_t nonce[CHACHA20_NONCE_LEN],
                    uint8_t       out[CHACHA20_BLOCK_LEN]) {
    /* Initial state. */
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e;
    s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = load_le32(key + i * 4);
    s[12] = counter;
    s[13] = load_le32(nonce + 0);
    s[14] = load_le32(nonce + 4);
    s[15] = load_le32(nonce + 8);

    uint32_t x[16];
    memcpy(x, s, sizeof(x));

    for (int i = 0; i < 10; i++) {
        /* Column round */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* Diagonal round */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; i++) {
        store_le32(out + i * 4, x[i] + s[i]);
    }
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY_LEN],
                  uint32_t      counter,
                  const uint8_t nonce[CHACHA20_NONCE_LEN],
                  const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t ks[CHACHA20_BLOCK_LEN];
    while (len > 0) {
        chacha20_block(key, counter, nonce, ks);
        size_t take = len < CHACHA20_BLOCK_LEN ? len : CHACHA20_BLOCK_LEN;
        for (size_t i = 0; i < take; i++) out[i] = in[i] ^ ks[i];
        in += take; out += take; len -= take;
        counter++;
    }
    memset(ks, 0, sizeof(ks));
}
