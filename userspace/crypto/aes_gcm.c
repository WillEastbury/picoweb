/*
 * AES-128-GCM (NIST SP 800-38D).
 *
 * - GCTR: AES-CTR with a 32-bit counter starting at 1 over J0.
 * - GHASH: polynomial hash over GF(2^128) with reduction polynomial
 *          x^128 + x^7 + x^2 + x + 1 (per NIST §6.3, big-endian
 *          bit ordering). H = AES_K(0^128).
 * - For the standard 96-bit IV case, J0 = IV || 0x00000001.
 *
 * Pure C, no T-tables. Spike-grade reference. Not constant-time.
 * Production hardening will use ARMv8 PMULL + AES intrinsics.
 */
#include "aes_gcm.h"

#include "aes.h"

#include <string.h>

static void xor16(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 16; i++) dst[i] = a[i] ^ b[i];
}

static void xor16_inplace(uint8_t* dst, const uint8_t* a) {
    for (int i = 0; i < 16; i++) dst[i] ^= a[i];
}

/* GF(2^128) multiply, NIST big-endian convention.
 * Inputs and output are 16-byte big-endian field elements.
 *
 * Algorithm: bit-serial right-shift method over Y, conditional XOR
 * of X into Z, with reduction by R = 0xE1 || 0^120 whenever the
 * bottom bit of V (initially X) is shifted out.
 *
 * Reference: NIST SP 800-38D, Algorithm 1 ("Multiplication on Blocks").
 */
static void gf128_mul(uint8_t z[16], const uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16];
    memcpy(v, x, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 128; i++) {
        /* If bit (15 - i/8)*8 + (7 - i%8) of Y is set... actually,
         * NIST bit numbering: bit i of byte j is the (7-i)-th MSB.
         * Y_i in NIST is the i-th bit of Y read MSB-first across
         * the 16 bytes: byte = i / 8, bit = 7 - (i % 8). */
        int byte = i >> 3;
        int bit  = 7 - (i & 7);
        if ((y[byte] >> bit) & 1) {
            xor16_inplace(z, v);
        }
        /* V = V >> 1, with reduction if low bit was 1.
         * Low bit in NIST = bit 127 = byte 15, bit 0 (LSB). */
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j-1] & 1) << 7));
        }
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
}

/* GHASH(H, A || C || len(A)||len(C)). The caller passes A and C
 * already padded to 16-byte boundaries. */
static void ghash(uint8_t y[16],
                  const uint8_t H[16],
                  const uint8_t* aad, size_t aad_len,
                  const uint8_t* ct,  size_t ct_len) {
    memset(y, 0, 16);
    uint8_t blk[16];

    /* AAD blocks. */
    size_t off = 0;
    while (off + 16 <= aad_len) {
        xor16_inplace(y, aad + off);
        gf128_mul(y, y, H);
        off += 16;
    }
    if (off < aad_len) {
        memset(blk, 0, 16);
        memcpy(blk, aad + off, aad_len - off);
        xor16_inplace(y, blk);
        gf128_mul(y, y, H);
    }

    /* Ciphertext blocks. */
    off = 0;
    while (off + 16 <= ct_len) {
        xor16_inplace(y, ct + off);
        gf128_mul(y, y, H);
        off += 16;
    }
    if (off < ct_len) {
        memset(blk, 0, 16);
        memcpy(blk, ct + off, ct_len - off);
        xor16_inplace(y, blk);
        gf128_mul(y, y, H);
    }

    /* Final block: 64-bit big-endian bit-lengths. */
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)ct_len  * 8;
    memset(blk, 0, 16);
    for (int i = 0; i < 8; i++) blk[i]     = (uint8_t)(aad_bits >> (56 - 8*i));
    for (int i = 0; i < 8; i++) blk[8 + i] = (uint8_t)(ct_bits  >> (56 - 8*i));
    xor16_inplace(y, blk);
    gf128_mul(y, y, H);
}

/* GCTR with starting counter J = J0 + 1 (i.e. the IV-derived block
 * with counter incremented). Encrypts in_len bytes. */
static void gctr(const aes128_ctx_t* aes,
                 const uint8_t J0[16],
                 const uint8_t* in, size_t in_len,
                 uint8_t* out) {
    uint8_t cb[16];
    memcpy(cb, J0, 16);
    /* Increment 32-bit counter (low 4 bytes). */
    for (int i = 15; i >= 12; i--) {
        if (++cb[i]) break;
    }

    uint8_t ks[16];
    size_t off = 0;
    while (off + 16 <= in_len) {
        aes128_encrypt_block(aes, cb, ks);
        for (int i = 0; i < 16; i++) out[off + i] = in[off + i] ^ ks[i];
        for (int i = 15; i >= 12; i--) { if (++cb[i]) break; }
        off += 16;
    }
    if (off < in_len) {
        aes128_encrypt_block(aes, cb, ks);
        for (size_t i = 0; i < in_len - off; i++) {
            out[off + i] = in[off + i] ^ ks[i];
        }
    }
}

void aes128_gcm_seal(const uint8_t key[AES128_GCM_KEY_LEN],
                     const uint8_t iv [AES128_GCM_IV_LEN],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* pt,  size_t pt_len,
                     uint8_t* ct,
                     uint8_t  tag[AES128_GCM_TAG_LEN]) {
    aes128_ctx_t aes;
    aes128_init(&aes, key);

    /* H = AES_K(0^128). */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    aes128_encrypt_block(&aes, zero, H);

    /* J0 for 96-bit IV: IV || 0x00000001. */
    uint8_t J0[16];
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    /* Encrypt plaintext under counter starting at inc(J0). */
    if (pt_len) gctr(&aes, J0, pt, pt_len, ct);

    /* GHASH over (AAD || CT || len fields). */
    uint8_t S[16];
    ghash(S, H, aad, aad_len, ct, pt_len);

    /* Tag = AES_K(J0) XOR S. */
    uint8_t EJ0[16];
    aes128_encrypt_block(&aes, J0, EJ0);
    xor16(tag, EJ0, S);
}

int aes128_gcm_open(const uint8_t key[AES128_GCM_KEY_LEN],
                    const uint8_t iv [AES128_GCM_IV_LEN],
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* ct,  size_t ct_len,
                    const uint8_t  tag[AES128_GCM_TAG_LEN],
                    uint8_t* pt) {
    aes128_ctx_t aes;
    aes128_init(&aes, key);

    uint8_t zero[16] = {0};
    uint8_t H[16];
    aes128_encrypt_block(&aes, zero, H);

    uint8_t J0[16];
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    /* Compute tag over the supplied ciphertext FIRST, before
     * decrypting, so a forged tag does not leak partial plaintext. */
    uint8_t S[16];
    ghash(S, H, aad, aad_len, ct, ct_len);
    uint8_t EJ0[16], expect_tag[16];
    aes128_encrypt_block(&aes, J0, EJ0);
    xor16(expect_tag, EJ0, S);

    /* Constant-time tag compare. */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= expect_tag[i] ^ tag[i];
    if (diff) return -1;

    /* Tag OK -> decrypt. */
    if (ct_len) gctr(&aes, J0, ct, ct_len, pt);
    return 0;
}
