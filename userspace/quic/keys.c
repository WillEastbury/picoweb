#include "keys.h"
#include "../tls/keysched.h"

#include <string.h>

int quic_keys_from_secret(const uint8_t* secret, size_t secret_len,
                          size_t key_len, size_t hp_len,
                          quic_keys_t* out)
{
    if (secret_len != 32) return 0;  /* SHA-256 only for now */
    if (key_len != 16 && key_len != 32) return 0;
    if (hp_len  != 16 && hp_len  != 32) return 0;

    tls13_hkdf_expand_label(secret, "quic key",
                            NULL, 0,
                            out->key, key_len);
    tls13_hkdf_expand_label(secret, "quic iv",
                            NULL, 0,
                            out->iv, QUIC_IV_LEN);
    tls13_hkdf_expand_label(secret, "quic hp",
                            NULL, 0,
                            out->hp, hp_len);
    out->key_len = (uint8_t)key_len;
    out->hp_len  = (uint8_t)hp_len;
    return 1;
}

void quic_key_update_next(const uint8_t* current_secret,
                          size_t secret_len,
                          uint8_t* out)
{
    /* Spec says output is the same length as the secret (hash output
     * length). We require 32 here too for now; tls13_hkdf_expand_label
     * is happy to produce arbitrary lengths via HKDF-Expand. */
    tls13_hkdf_expand_label(current_secret, "quic ku",
                            NULL, 0,
                            out, secret_len);
}
