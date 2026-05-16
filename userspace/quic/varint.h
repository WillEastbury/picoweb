/*
 * QUIC variable-length integer encoding (RFC 9000 §16).
 *
 *   2 MSBs of first byte select the length: 00=1B, 01=2B, 10=4B, 11=8B.
 *   Value occupies the remaining bits (big-endian).
 *
 *   Range:
 *     1 byte  : 0          .. 63              (2^6 - 1)
 *     2 bytes : 0          .. 16383           (2^14 - 1)
 *     4 bytes : 0          .. 1073741823      (2^30 - 1)
 *     8 bytes : 0          .. 4611686018427387903 (2^62 - 1)
 */
#ifndef PICOWEB_USERSPACE_QUIC_VARINT_H
#define PICOWEB_USERSPACE_QUIC_VARINT_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_VARINT_MAX UINT64_C(0x3fffffffffffffff)  /* 2^62 - 1 */

/* Encode `v` into `out` (up to 8 bytes). Returns bytes written, or
 * 0 if v exceeds QUIC_VARINT_MAX or out_cap is insufficient. */
size_t quic_varint_encode(uint8_t* out, size_t out_cap, uint64_t v);

/* Decode varint from `in`. On success returns bytes consumed (1, 2,
 * 4, or 8) and writes value to *v. Returns 0 if `in_len` is too
 * small for the encoded length. */
size_t quic_varint_decode(const uint8_t* in, size_t in_len, uint64_t* v);

/* Length of the encoding of `v`, without writing anything. */
size_t quic_varint_size(uint64_t v);

#endif
