/*
 * HTTP/3 frame layer (RFC 9114 §7).
 *
 * HTTP/3 frames are length-delimited records carried inside QUIC
 * STREAM frames. Each frame is:
 *
 *   Type   : varint (RFC 9000 §16)
 *   Length : varint
 *   Payload: Length bytes
 *
 * This module is a pure wire codec — it does not own a stream or
 * speak to QUIC. The caller (h3 connection layer) feeds it bytes
 * pulled from a QUIC stream's reassembled in-order prefix.
 *
 * QPACK encoding of HEADERS payload is NOT done here; HEADERS bytes
 * are passed through opaque.
 */
#ifndef PICOWEB_USERSPACE_H3_H3_H
#define PICOWEB_USERSPACE_H3_H3_H

#include <stdint.h>
#include <stddef.h>

/* RFC 9114 §7.2 frame types we parse / emit. Reserved frame types
 * (HTTP/2 GOAWAY/PUSH_PROMISE/PING that MUST be treated as errors
 * in h3 per §7.2.8) are reported as H3_FT_RESERVED so the caller
 * can raise H3_FRAME_UNEXPECTED. Unknown types per §9 grease are
 * reported as H3_FT_UNKNOWN — the caller MUST skip them silently. */
typedef enum {
    H3_FT_DATA          = 0x00,
    H3_FT_HEADERS       = 0x01,
    H3_FT_CANCEL_PUSH   = 0x03,
    H3_FT_SETTINGS      = 0x04,
    H3_FT_PUSH_PROMISE  = 0x05,
    H3_FT_GOAWAY        = 0x07,
    H3_FT_MAX_PUSH_ID   = 0x0d,
    /* Synthetic — caller-friendly classification: */
    H3_FT_RESERVED      = 0xfe,  /* §7.2.8 reserved-for-error type */
    H3_FT_UNKNOWN       = 0xff   /* unknown / grease — must skip */
} h3_frame_type_t;

typedef struct {
    h3_frame_type_t type;
    uint64_t        raw_type;     /* original varint, for grease echo */
    uint64_t        length;       /* payload length in bytes */
    const uint8_t*  payload;      /* points into caller buffer; payload may be empty */
} h3_frame_t;

#define H3_DECODE_NEED_MORE  ((size_t)0)
#define H3_DECODE_ERROR      ((size_t)-1)

/* Decode one frame from in[0..in_len). Returns:
 *   >0  bytes consumed (header + payload), *out filled
 *   0   need more bytes
 *  -1  permanent decode error (bad varint, length > caller-allowed)
 *
 * Caller MUST cap accepted Length values at a per-stream policy (e.g.
 * ~64 KiB for HEADERS, more for DATA on bulk transfers). This codec
 * does not enforce a maximum — it only validates varint encoding.
 */
size_t h3_frame_decode(const uint8_t* in, size_t in_len, h3_frame_t* out);

/* Classify a raw varint type into one of the H3_FT_* codes. Pure
 * function over the type number, exposed for tests / inspection. */
h3_frame_type_t h3_classify_type(uint64_t raw_type);

/* Encode a frame header (type + length varints) into out. Returns
 * bytes written, 0 on overflow. Caller writes the payload separately. */
size_t h3_frame_header_encode(uint8_t* out, size_t cap,
                              uint64_t type, uint64_t length);

/* Convenience: encode header + copy payload in one shot. Returns
 * total bytes written. */
size_t h3_frame_encode(uint8_t* out, size_t cap,
                       uint64_t type,
                       const uint8_t* payload, size_t payload_len);

/* ---- SETTINGS payload helpers (RFC 9114 §7.2.4) -------------- */

/* SETTINGS payload is a sequence of (identifier varint, value varint)
 * pairs. We provide a small builder that appends a setting; on
 * overflow the buffer is left untouched and 0 returned. */
size_t h3_settings_append(uint8_t* out, size_t cap, size_t cur_len,
                          uint64_t identifier, uint64_t value);

/* Iterate SETTINGS payload. *cursor begins at 0; on each call advances
 * past one (id, value) pair. Returns:
 *    1  pair decoded into *out_id / *out_val
 *    0  end of payload
 *   -1  malformed (truncated varint or trailing garbage)
 */
int h3_settings_next(const uint8_t* payload, size_t payload_len,
                     size_t* cursor,
                     uint64_t* out_id, uint64_t* out_val);

/* Known SETTINGS identifiers (RFC 9114 §7.2.4.1, §RFC 9204 §5). */
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY  0x01
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE    0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS     0x07

/* ---- High-level response builder (RFC 9114 + RFC 9204) ------- */

/* Build a complete h3 server response on a single buffer:
 *
 *   [HEADERS frame] [DATA frame]
 *
 * The HEADERS payload is a QPACK-encoded field section with:
 *   :status         <status_code> (indexed-static when in {103, 200,
 *                    204, 206, 304, 400, 403, 404, 421, 425, 500},
 *                    else literal-with-static-name idx 24 + value)
 *   content-type    static-table indexed where possible, else
 *                    literal-with-static-name idx 53 + Huffman value
 *   content-length  literal-with-static-name idx 4 + Huffman value
 *
 * If `ctype` is NULL or empty, the content-type field is omitted.
 * If `body` is NULL, the DATA frame is omitted (HEADERS-only response,
 * e.g. 304 Not Modified).
 *
 * Returns total bytes written, or 0 on overflow / unsupported status. */
size_t h3_build_response(uint8_t* out, size_t cap,
                         unsigned status_code,
                         const char* ctype, size_t ctype_len,
                         const uint8_t* body, size_t body_len);

#endif
