/*
 * Minimal PEM decoder (RFC 7468).
 *
 * PEM format:
 *
 *   -----BEGIN <LABEL>-----
 *   <base64-encoded DER, optionally line-wrapped>
 *   -----END <LABEL>-----
 *
 * We accept any whitespace/CR/LF between BEGIN and END markers and
 * inside the base64 body. We require an exact label match for
 * security (preventing key/cert confusion). The function strips
 * everything outside the BEGIN..END block.
 *
 * Output capacity: DER is at most 3/4 of the base64 length, so a
 * caller can size out_cap as `pem_len` and always have headroom.
 *
 * No allocations — output goes into a caller-provided buffer.
 *
 * Use cases:
 *   - Decode `_certs/server.crt`  (label = "CERTIFICATE")
 *   - Decode `_certs/server.key`  (label = "PRIVATE KEY" for PKCS#8,
 *                                  or "EC PRIVATE KEY" for SEC1 ECDSA)
 *   - Decode an env-supplied PEM blob
 */
#ifndef PICOWEB_USERSPACE_TLS_PEM_H
#define PICOWEB_USERSPACE_TLS_PEM_H

#include <stddef.h>
#include <stdint.h>

/* Decode the FIRST PEM object in `pem_in` whose label equals
 * `expected_label`. Returns the number of DER bytes written to
 * `out`, or -1 on error (label mismatch, bad base64, truncated,
 * or out_cap too small).
 *
 * The decoder ignores whitespace and stops at the first END marker
 * for the matching label. */
int pem_decode(const char* pem_in, size_t pem_len,
               const char* expected_label,
               uint8_t* out, size_t out_cap);

/* Decode every PEM block matching `expected_label` and concatenate
 * their DER blobs in order. Useful for cert chains where the file
 * contains [server cert] [intermediate CA] [root CA] back-to-back.
 * Returns total DER bytes written, or -1 on error. */
int pem_decode_chain(const char* pem_in, size_t pem_len,
                     const char* expected_label,
                     uint8_t* out, size_t out_cap,
                     /* out: number of certs concatenated */
                     int* out_count);

#endif
