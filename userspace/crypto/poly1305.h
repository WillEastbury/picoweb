/*
 * Poly1305 (RFC 8439 §2.5) — one-time authenticator.
 *
 * Tag = (((sum_of_blocks * r) + s) mod (2^130 - 5)) mod 2^128
 *
 * The key is 32 bytes split into r (16) and s (16). r has 22 bits
 * masked out per RFC 8439 §2.5 ("clamping"). s is added at the end.
 *
 * NEVER reuse the same (r,s) for two different messages — the
 * mathematical assumptions break and key recovery is trivial. In our
 * AEAD construction we derive a fresh (r,s) per record from the
 * ChaCha20 keystream block 0; that's the standard pattern.
 */
#ifndef PICOWEB_USERSPACE_CRYPTO_POLY1305_H
#define PICOWEB_USERSPACE_CRYPTO_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define POLY1305_KEY_LEN 32u
#define POLY1305_TAG_LEN 16u

void poly1305(const uint8_t key[POLY1305_KEY_LEN],
              const uint8_t* msg, size_t len,
              uint8_t       tag[POLY1305_TAG_LEN]);

#endif
