#ifndef PW_ECDSA_H
#define PW_ECDSA_H

#include <stddef.h>
#include <stdint.h>

/* ECDSA-P256-SHA256 sign with RFC 6979 deterministic k.
 * msg is hashed with SHA-256 internally. */
int ecdsa_p256_sha256_sign(const uint8_t priv[32],
                           const uint8_t* msg, size_t msg_n,
                           uint8_t out_r[32], uint8_t out_s[32]);

/* DER-encode (r, s) as SEQUENCE { INTEGER r, INTEGER s }. */
int ecdsa_p256_encode_der(const uint8_t r[32], const uint8_t s[32],
                          uint8_t* out, size_t out_cap);

/* Raw TLS-legacy/JWS style helper: out = r || s. TLS 1.3 CV uses DER. */
int ecdsa_p256_encode_raw64(const uint8_t r[32], const uint8_t s[32],
                            uint8_t out[64]);

#endif
