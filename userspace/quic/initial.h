/*
 * QUIC version-1 Initial keys (RFC 9001 §5.2).
 *
 * Initial keys are derived deterministically from the client's
 * Destination Connection ID. Both endpoints derive the same keys,
 * so this is an obfuscation layer (not security) — its purpose is
 * to filter out non-QUIC UDP traffic and to preserve protocol
 * extensibility.
 *
 *   initial_salt    = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
 *   initial_secret  = HKDF-Extract(initial_salt, dcid)
 *   client_initial_secret = HKDF-Expand-Label(initial_secret,
 *                                             "client in", "", 32)
 *   server_initial_secret = HKDF-Expand-Label(initial_secret,
 *                                             "server in", "", 32)
 *
 * From each per-direction secret we further derive:
 *   key = HKDF-Expand-Label(secret, "quic key", "", 16)  -> AES-128
 *   iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
 *   hp  = HKDF-Expand-Label(secret, "quic hp",  "", 16)  -> AES-128
 */
#ifndef PICOWEB_USERSPACE_QUIC_INITIAL_H
#define PICOWEB_USERSPACE_QUIC_INITIAL_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_INITIAL_KEY_LEN 16u
#define QUIC_INITIAL_IV_LEN  12u
#define QUIC_INITIAL_HP_LEN  16u

/* Per-direction Initial protection material. */
typedef struct {
    uint8_t key[QUIC_INITIAL_KEY_LEN];
    uint8_t iv [QUIC_INITIAL_IV_LEN];
    uint8_t hp [QUIC_INITIAL_HP_LEN];
} quic_initial_keys_t;

/* Derive per-direction Initial secret + AEAD key/iv + header-
 * protection key from the client's Destination Connection ID.
 *
 * `is_server` non-zero -> derive server_initial_secret -> server keys.
 * `is_server` zero     -> derive client_initial_secret -> client keys.
 */
void quic_initial_derive(const uint8_t* dcid, size_t dcid_len,
                         int is_server,
                         quic_initial_keys_t* out);

#endif
