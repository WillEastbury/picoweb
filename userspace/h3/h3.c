/* HTTP/3 frame layer — see h3.h. */
#include "h3.h"
#include "../quic/varint.h"

#include <string.h>

h3_frame_type_t h3_classify_type(uint64_t raw_type)
{
    switch (raw_type) {
    case 0x00: return H3_FT_DATA;
    case 0x01: return H3_FT_HEADERS;
    case 0x03: return H3_FT_CANCEL_PUSH;
    case 0x04: return H3_FT_SETTINGS;
    case 0x05: return H3_FT_PUSH_PROMISE;
    case 0x07: return H3_FT_GOAWAY;
    case 0x0d: return H3_FT_MAX_PUSH_ID;
    default:
        /* RFC 9114 §7.2.8 — h2-reserved frame types that MUST be
         * treated as error: 0x02 (PRIORITY in h2), 0x06 (PING in h2),
         * 0x08 (WINDOW_UPDATE in h2), 0x09 (CONTINUATION in h2). */
        if (raw_type == 0x02 || raw_type == 0x06 ||
            raw_type == 0x08 || raw_type == 0x09) {
            return H3_FT_RESERVED;
        }
        /* RFC 9114 §7.2.8 + §9 grease — unknown types must be
         * skipped silently. */
        return H3_FT_UNKNOWN;
    }
}

size_t h3_frame_decode(const uint8_t* in, size_t in_len, h3_frame_t* out)
{
    if (!in || !out) return H3_DECODE_ERROR;
    if (in_len == 0) return H3_DECODE_NEED_MORE;

    size_t off = 0;
    uint64_t type = 0;
    size_t n = quic_varint_decode(in + off, in_len - off, &type);
    if (n == 0) return H3_DECODE_NEED_MORE;
    off += n;

    uint64_t length = 0;
    if (off >= in_len) return H3_DECODE_NEED_MORE;
    n = quic_varint_decode(in + off, in_len - off, &length);
    if (n == 0) return H3_DECODE_NEED_MORE;
    off += n;

    /* Payload bytes — need length more bytes available. */
    if (length > (uint64_t)(in_len - off)) return H3_DECODE_NEED_MORE;

    out->raw_type = type;
    out->type     = h3_classify_type(type);
    out->length   = length;
    out->payload  = (length > 0) ? (in + off) : NULL;
    return off + (size_t)length;
}

size_t h3_frame_header_encode(uint8_t* out, size_t cap,
                              uint64_t type, uint64_t length)
{
    if (!out) return 0;
    size_t n1 = quic_varint_encode(out, cap, type);
    if (n1 == 0) return 0;
    size_t n2 = quic_varint_encode(out + n1, cap - n1, length);
    if (n2 == 0) return 0;
    return n1 + n2;
}

size_t h3_frame_encode(uint8_t* out, size_t cap,
                       uint64_t type,
                       const uint8_t* payload, size_t payload_len)
{
    if (!out) return 0;
    size_t hdr = h3_frame_header_encode(out, cap, type, (uint64_t)payload_len);
    if (hdr == 0) return 0;
    if (cap - hdr < payload_len) return 0;
    if (payload_len > 0) {
        if (!payload) return 0;
        memcpy(out + hdr, payload, payload_len);
    }
    return hdr + payload_len;
}

/* ---- SETTINGS ----------------------------------------------- */

size_t h3_settings_append(uint8_t* out, size_t cap, size_t cur_len,
                          uint64_t identifier, uint64_t value)
{
    if (!out || cur_len > cap) return 0;
    size_t off = cur_len;
    size_t n1 = quic_varint_encode(out + off, cap - off, identifier);
    if (n1 == 0) return 0;
    off += n1;
    size_t n2 = quic_varint_encode(out + off, cap - off, value);
    if (n2 == 0) return 0;
    off += n2;
    return off;
}

int h3_settings_next(const uint8_t* payload, size_t payload_len,
                     size_t* cursor,
                     uint64_t* out_id, uint64_t* out_val)
{
    if (!payload || !cursor || !out_id || !out_val) return -1;
    size_t off = *cursor;
    if (off > payload_len) return -1;
    if (off == payload_len) return 0;

    uint64_t id = 0, val = 0;
    size_t n1 = quic_varint_decode(payload + off, payload_len - off, &id);
    if (n1 == 0) return -1;
    off += n1;
    if (off >= payload_len) return -1;
    size_t n2 = quic_varint_decode(payload + off, payload_len - off, &val);
    if (n2 == 0) return -1;
    off += n2;

    *cursor  = off;
    *out_id  = id;
    *out_val = val;
    return 1;
}
