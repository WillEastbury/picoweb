/*
 * ChaCha20 stream cipher (RFC 8439 §2.4).
 *
 * Key:    32 bytes
 * Nonce:  12 bytes  (TLS 1.3 uses 12-byte nonces; original DJB
 *                    construction uses 8 bytes — RFC 8439 is the
 *                    12-byte variant and is what TLS expects)
 * Counter: 32-bit, starts at 0 for AEAD use
 *
 * The cipher is its own inverse: encrypt(encrypt(x)) == x.
 */
#ifndef PICOWEB_USERSPACE_CRYPTO_CHACHA20_H
#define PICOWEB_USERSPACE_CRYPTO_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY_LEN   32u
#define CHACHA20_NONCE_LEN 12u
#define CHACHA20_BLOCK_LEN 64u

/* Produces one 64-byte keystream block for (key, counter, nonce). */
void chacha20_block(const uint8_t key[CHACHA20_KEY_LEN],
                    uint32_t      counter,
                    const uint8_t nonce[CHACHA20_NONCE_LEN],
                    uint8_t       out[CHACHA20_BLOCK_LEN]);

/* Encrypt or decrypt `len` bytes by XORing with the keystream
 * starting at `counter`. `in` and `out` may alias. */
void chacha20_xor(const uint8_t key[CHACHA20_KEY_LEN],
                  uint32_t      counter,
                  const uint8_t nonce[CHACHA20_NONCE_LEN],
                  const uint8_t* in, uint8_t* out, size_t len);

#endif
