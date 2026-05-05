/*
 * SHA-256 (FIPS 180-4) — pure C, no intrinsics, no third-party code.
 *
 * Constant-time-ish: no data-dependent branches, no table lookups
 * indexed by secret data. Suitable for use inside HMAC keying.
 *
 * Reference: NIST FIPS PUB 180-4, August 2015.
 */
#ifndef PICOWEB_USERSPACE_CRYPTO_SHA256_H
#define PICOWEB_USERSPACE_CRYPTO_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32u
#define SHA256_BLOCK_LEN  64u

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[SHA256_BLOCK_LEN];
    size_t   buf_len;
} sha256_ctx;

void sha256_init(sha256_ctx* c);
void sha256_update(sha256_ctx* c, const void* data, size_t len);
void sha256_final(sha256_ctx* c, uint8_t out[SHA256_DIGEST_LEN]);

/* One-shot convenience. */
void sha256(const void* data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

#endif
