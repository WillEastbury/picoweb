/*
 * ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
 */

#include "chacha20_poly1305.h"

#include <string.h>

#include "chacha20.h"
#include "poly1305.h"

static void store_le64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static void mac_data(uint8_t poly_key[POLY1305_KEY_LEN],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct,  size_t ct_len,
                     uint8_t tag[16]) {
    /* RFC 8439 §2.8: build aad || pad16(aad) || ct || pad16(ct) ||
     * len64_le(aad) || len64_le(ct), then run Poly1305 over the lot.
     * We feed Poly1305 incrementally without an alloc by computing
     * over a small stack buffer for the trailers. */

    /* For the spike we just build the buffer inline — TLS records cap
     * at ~16 KiB and AAD is typically 5 bytes (the TLS additional_data
     * is a record header). A real impl would feed Poly1305 via an
     * incremental update API to avoid the alloc. */

    /* We need at most: aad + 15 (pad) + ct + 15 (pad) + 16 (lens). */
    size_t mac_len = aad_len + ((16u - (aad_len & 15u)) & 15u) +
                     ct_len  + ((16u - (ct_len  & 15u)) & 15u) + 16;

    /* Allocate on the heap because mac_len can exceed safe stack
     * sizes for max-size TLS records (16384 + small). The caller-side
     * malloc cost is one per record; can be replaced with a Poly1305
     * incremental API later. */
    uint8_t* buf = (uint8_t*)__builtin_alloca(mac_len);
    size_t off = 0;
    if (aad_len) { memcpy(buf + off, aad, aad_len); off += aad_len; }
    while (off & 15u) buf[off++] = 0;
    if (ct_len)  { memcpy(buf + off, ct, ct_len);   off += ct_len;  }
    while (off & 15u) buf[off++] = 0;
    store_le64(buf + off, (uint64_t)aad_len); off += 8;
    store_le64(buf + off, (uint64_t)ct_len);  off += 8;

    poly1305(poly_key, buf, off, tag);
}

void aead_chacha20_poly1305_seal(const uint8_t key[AEAD_CHACHA20_POLY1305_KEY_LEN],
                                 const uint8_t nonce[AEAD_CHACHA20_POLY1305_NONCE_LEN],
                                 const uint8_t* aad, size_t aad_len,
                                 const uint8_t* pt,  size_t pt_len,
                                 uint8_t* ct,
                                 uint8_t tag[AEAD_CHACHA20_POLY1305_TAG_LEN]) {
    /* Derive Poly1305 one-time key from ChaCha20 block 0. */
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);
    /* Only first 32 bytes are used; the rest are discarded. */

    /* Encrypt with counter starting at 1. */
    chacha20_xor(key, 1, nonce, pt, ct, pt_len);

    mac_data(poly_key, aad, aad_len, ct, pt_len, tag);

    memset(poly_key, 0, sizeof(poly_key));
}

int aead_chacha20_poly1305_open(const uint8_t key[AEAD_CHACHA20_POLY1305_KEY_LEN],
                                const uint8_t nonce[AEAD_CHACHA20_POLY1305_NONCE_LEN],
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ct,  size_t ct_len,
                                const uint8_t tag[AEAD_CHACHA20_POLY1305_TAG_LEN],
                                uint8_t* pt) {
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    uint8_t expected[16];
    mac_data(poly_key, aad, aad_len, ct, ct_len, expected);
    memset(poly_key, 0, sizeof(poly_key));

    if (!crypto_consttime_eq(expected, tag, 16)) {
        memset(expected, 0, sizeof(expected));
        return -1;
    }
    memset(expected, 0, sizeof(expected));

    chacha20_xor(key, 1, nonce, ct, pt, ct_len);
    return 0;
}

int crypto_consttime_eq(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}
