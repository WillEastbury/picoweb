/* QUIC v1 Initial-key derivation (RFC 9001 §5.2). */
#include "initial.h"

#include "../crypto/hkdf.h"
#include "../tls/keysched.h"

#include <string.h>

/* RFC 9001 §5.2: initial_salt for QUIC version 1. */
static const uint8_t QUIC_V1_INITIAL_SALT[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
};

void quic_initial_derive(const uint8_t* dcid, size_t dcid_len,
                         int is_server,
                         quic_initial_keys_t* out) {
    uint8_t initial_secret[HKDF_PRK_LEN];
    hkdf_extract(QUIC_V1_INITIAL_SALT, sizeof QUIC_V1_INITIAL_SALT,
                 dcid, dcid_len,
                 initial_secret);

    uint8_t side_secret[32];
    const char* side_label = is_server ? "server in" : "client in";
    /* tls13_hkdf_expand_label prepends "tls13 " — RFC 9001 §5.1
     * states QUIC reuses the TLS 1.3 HKDF-Expand-Label construction
     * verbatim. Output length 32 (SHA-256 size). */
    tls13_hkdf_expand_label(initial_secret, side_label,
                            NULL, 0,
                            side_secret, sizeof side_secret);

    tls13_hkdf_expand_label(side_secret, "quic key",
                            NULL, 0,
                            out->key, QUIC_INITIAL_KEY_LEN);
    tls13_hkdf_expand_label(side_secret, "quic iv",
                            NULL, 0,
                            out->iv,  QUIC_INITIAL_IV_LEN);
    tls13_hkdf_expand_label(side_secret, "quic hp",
                            NULL, 0,
                            out->hp,  QUIC_INITIAL_HP_LEN);
}
