/*
 * QUIC packet protection key derivation (RFC 9001 §5.1, §6.1).
 *
 * Given an epoch traffic secret (initial / handshake / 1-RTT, derived
 * by the TLS 1.3 key schedule with QUIC labels), produce the (key,
 * iv, hp) triple used for AEAD packet protection and header
 * protection.
 *
 * Also provides the §6.1 key-update derivation:
 *   next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", L)
 *
 * AEAD-agnostic at the API: the caller supplies key/iv/hp lengths.
 * For TLS_AES_128_GCM_SHA256 (the only suite picoweb implements
 * today) those are 16 / 12 / 16 bytes respectively.
 */
#ifndef PICOWEB_USERSPACE_QUIC_KEYS_H
#define PICOWEB_USERSPACE_QUIC_KEYS_H

#include <stdint.h>
#include <stddef.h>

/* Hard upper bounds for our supported suites. */
#define QUIC_KEY_MAX_LEN    32  /* AES-256 */
#define QUIC_IV_LEN         12  /* fixed by AEAD nonce shape */
#define QUIC_HP_MAX_LEN     32

typedef struct {
    uint8_t key[QUIC_KEY_MAX_LEN];
    uint8_t iv [QUIC_IV_LEN];
    uint8_t hp [QUIC_HP_MAX_LEN];
    uint8_t key_len;
    uint8_t hp_len;
} quic_keys_t;

/* Derive (key, iv, hp) from an epoch traffic secret using the QUIC
 * labels "quic key", "quic iv", "quic hp" (RFC 9001 §5.1). Writes
 * key_len / hp_len. iv length is always QUIC_IV_LEN. Currently
 * supports key_len in {16, 32} and hp_len in {16, 32}; passing other
 * values causes the function to leave `out` unchanged and return 0. */
int quic_keys_from_secret(const uint8_t* secret, size_t secret_len,
                          size_t key_len, size_t hp_len,
                          quic_keys_t* out);

/* Compute next-generation traffic secret per RFC 9001 §6.1.
 * `out` MUST have capacity `secret_len`. */
void quic_key_update_next(const uint8_t* current_secret,
                          size_t secret_len,
                          uint8_t* out);

#endif
