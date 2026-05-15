/*
 * AES-128-GCM AEAD (NIST SP 800-38D / RFC 5288).
 *
 * Used by:
 *   - userspace/quic/initial.c : RFC 9001 Initial-key AEAD
 *   - userspace/tls (future)   : TLS 1.3 AES-GCM cipher suites
 *
 * Public API mirrors crypto/chacha20_poly1305.h to keep callers
 * cipher-agnostic. Currently only the 12-byte (96-bit) IV variant
 * is supported, which is what TLS 1.3 and QUIC both use.
 */
#ifndef PICOWEB_USERSPACE_CRYPTO_AES_GCM_H
#define PICOWEB_USERSPACE_CRYPTO_AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#define AES128_GCM_KEY_LEN 16u
#define AES128_GCM_IV_LEN  12u
#define AES128_GCM_TAG_LEN 16u

/* Seal: encrypt `pt` (length `pt_len`) under (key, iv) with
 * additional authenticated data `aad` (length `aad_len`). Writes
 * ciphertext to `ct` (must hold pt_len bytes; may equal pt) and
 * the 16-byte authentication tag to `tag`. */
void aes128_gcm_seal(const uint8_t key[AES128_GCM_KEY_LEN],
                     const uint8_t iv [AES128_GCM_IV_LEN],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* pt,  size_t pt_len,
                     uint8_t* ct,
                     uint8_t  tag[AES128_GCM_TAG_LEN]);

/* Open: verify tag and decrypt. Returns 0 on success (and writes
 * plaintext to `pt`), -1 if the tag does not verify (in which case
 * the contents of `pt` MUST NOT be used). */
int aes128_gcm_open(const uint8_t key[AES128_GCM_KEY_LEN],
                    const uint8_t iv [AES128_GCM_IV_LEN],
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* ct,  size_t ct_len,
                    const uint8_t  tag[AES128_GCM_TAG_LEN],
                    uint8_t* pt);

#endif
