/*
 * AES-128 (FIPS-197). Single-block ECB encryption only — that's all
 * we need for QUIC header protection (RFC 9001 §5.4) and for the
 * GCTR/GHASH primitives in our AES-128-GCM.
 *
 * Spike-grade reference implementation: byte-oriented S-box and
 * MixColumns. Not constant-time (S-box lookups can leak via cache
 * timing). For production we'll add an ARMv8 AES intrinsics path
 * (see crypto/sha256_armv8.c for the project pattern); the public
 * API here is stable so callers don't change when that lands.
 */
#ifndef PICOWEB_USERSPACE_CRYPTO_AES_H
#define PICOWEB_USERSPACE_CRYPTO_AES_H

#include <stdint.h>
#include <stddef.h>

#define AES128_KEY_LEN    16u
#define AES128_BLOCK_LEN  16u
#define AES128_NR         10u            /* number of rounds */
#define AES128_RK_WORDS   ((AES128_NR + 1) * 4)   /* 44 words */

typedef struct {
    uint32_t rk[AES128_RK_WORDS];        /* expanded round keys */
} aes128_ctx_t;

/* Expand a 16-byte key into round-key schedule. */
void aes128_init(aes128_ctx_t* ctx, const uint8_t key[AES128_KEY_LEN]);

/* Encrypt one 16-byte block. in/out may overlap. */
void aes128_encrypt_block(const aes128_ctx_t* ctx,
                          const uint8_t in[AES128_BLOCK_LEN],
                          uint8_t out[AES128_BLOCK_LEN]);

#endif
