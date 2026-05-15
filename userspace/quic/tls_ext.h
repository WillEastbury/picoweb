/*
 * QUIC↔TLS extension wiring (RFC 9001 §8.2).
 *
 * The QUIC transport-parameters blob (built by quic_tp_encode) is
 * carried inside the TLS 1.3 handshake under extension codepoint
 * 0x0039 ("quic_transport_parameters"). The client puts it in the
 * ClientHello; the server echoes its own TPs in the
 * EncryptedExtensions.
 *
 * This module provides the pure byte-level glue:
 *   - quic_tls_ext_emit_tp:   wrap a TP blob in a TLS extension TLV.
 *   - quic_tls_ext_find_tp:   locate the TP extension inside an
 *                             extensions block and return its body.
 *
 * No TLS state is touched; the TLS handshake state machine (phase
 * 5e) calls these to splice the extension in/out of the existing
 * extensions blocks.
 */
#ifndef PICOWEB_USERSPACE_QUIC_TLS_EXT_H
#define PICOWEB_USERSPACE_QUIC_TLS_EXT_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_TLS_EXT_TRANSPORT_PARAMETERS 0x0039u

/* Emit a single TLS 1.3 extension TLV into `out`:
 *
 *     u16 ext_type = 0x0039
 *     u16 ext_data_length
 *     opaque ext_data[ext_data_length]   // = tp_blob
 *
 * Returns total bytes written (4 + tp_blob_len) on success, or 0 if
 * out_cap is insufficient or tp_blob_len exceeds 0xffff. tp_blob may
 * be NULL only if tp_blob_len == 0. */
size_t quic_tls_ext_emit_tp(uint8_t* out, size_t out_cap,
                            const uint8_t* tp_blob, size_t tp_blob_len);

/* Locate the QUIC transport-parameters extension inside a TLS 1.3
 * extensions block (the body of a `<0..2^16-1>` extensions list, NOT
 * including the outer u16 length).
 *
 * On success: returns 1, sets *out_body to a pointer inside
 * `ext_block` and *out_body_len to its length.
 * On absence: returns 0 (out params untouched).
 * On malformed block (truncated TLV): returns -1.
 *
 * If the extension appears more than once, returns -1 (per
 * RFC 8446 §4.2: extensions in a given block must not appear more
 * than once). */
int quic_tls_ext_find_tp(const uint8_t* ext_block, size_t ext_block_len,
                         const uint8_t** out_body, size_t* out_body_len);

#endif
