/* HTTP/3 frame layer — see h3.h. */
#include "h3.h"
#include "../quic/varint.h"
#include "../qpack/qpack.h"

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

/* ---- High-level response builder ---------------------------- */

static int h3_status_static_index(unsigned code, uint64_t* idx)
{
    switch (code) {
    case 103: *idx = 24; return 1;
    case 200: *idx = 25; return 1;
    case 304: *idx = 26; return 1;
    case 404: *idx = 27; return 1;
    case 503: *idx = 28; return 1;
    case 100: *idx = 63; return 1;
    case 204: *idx = 64; return 1;
    case 206: *idx = 65; return 1;
    case 302: *idx = 66; return 1;
    case 400: *idx = 67; return 1;
    case 403: *idx = 68; return 1;
    case 421: *idx = 69; return 1;
    case 425: *idx = 70; return 1;
    case 500: *idx = 71; return 1;
    default:  return 0;
    }
}

/* Lookup an indexed content-type for common values. Returns 1 + sets
 * *idx if the static table has it pre-bound; 0 otherwise. */
static int h3_ctype_static_index(const char* ct, size_t ct_len, uint64_t* idx)
{
    struct { const char* v; size_t l; uint64_t i; } map[] = {
        {"application/dns-message",        23, 44},
        {"application/javascript",         22, 45},
        {"application/json",               16, 46},
        {"application/x-www-form-urlencoded", 33, 47},
        {"image/gif",                       9, 48},
        {"image/jpeg",                     10, 49},
        {"image/png",                       9, 50},
        {"text/css",                        8, 51},
        {"text/html; charset=utf-8",       24, 52},
        {"text/plain",                     10, 53},
        {"text/plain;charset=utf-8",       24, 54},
    };
    for (size_t k = 0; k < sizeof map / sizeof map[0]; ++k) {
        if (map[k].l == ct_len && memcmp(map[k].v, ct, ct_len) == 0) {
            *idx = map[k].i;
            return 1;
        }
    }
    return 0;
}

size_t h3_build_response(uint8_t* out, size_t cap,
                         unsigned status_code,
                         const char* ctype, size_t ctype_len,
                         const uint8_t* body, size_t body_len)
{
    if (!out) return 0;

    /* Build field section into a scratch buffer first so we know its
     * length (required to emit the HEADERS frame header). */
    uint8_t fs[512];
    size_t  fo = 0;
    size_t  n  = qpack_encode_prefix_empty(fs + fo, sizeof fs - fo);
    if (n == 0) return 0;
    fo += n;

    /* :status */
    uint64_t idx;
    if (h3_status_static_index(status_code, &idx)) {
        n = qpack_encode_indexed_static(fs + fo, sizeof fs - fo, idx);
        if (n == 0) return 0;
        fo += n;
    } else {
        char buf[8];
        if (status_code > 999) return 0;
        int  bl = 0;
        unsigned s = status_code ? status_code : 0;
        if (s == 0) { buf[bl++] = '0'; }
        else {
            char tmp[8]; int tl = 0;
            while (s) { tmp[tl++] = (char)('0' + s % 10); s /= 10; }
            while (tl) buf[bl++] = tmp[--tl];
        }
        /* idx 24 = ":status" with value "103"; we override with literal. */
        n = qpack_encode_literal_static_name(fs + fo, sizeof fs - fo,
                                             24, (const uint8_t*)buf, (size_t)bl);
        if (n == 0) return 0;
        fo += n;
    }

    /* content-type (optional) */
    if (ctype && ctype_len) {
        if (h3_ctype_static_index(ctype, ctype_len, &idx)) {
            n = qpack_encode_indexed_static(fs + fo, sizeof fs - fo, idx);
        } else {
            /* idx 53 = "content-type: text/plain"; override value Huffman'd. */
            n = qpack_encode_literal_static_name_huff(fs + fo, sizeof fs - fo,
                                                      53,
                                                      (const uint8_t*)ctype,
                                                      ctype_len);
        }
        if (n == 0) return 0;
        fo += n;
    }

    /* content-length */
    if (body) {
        char     clbuf[24];
        int      cl = 0;
        size_t   bl = body_len;
        if (bl == 0) { clbuf[cl++] = '0'; }
        else {
            char tmp[24]; int tl = 0;
            while (bl) { tmp[tl++] = (char)('0' + bl % 10); bl /= 10; }
            while (tl) clbuf[cl++] = tmp[--tl];
        }
        /* idx 4 = "content-length: 0"; override value with our number. */
        n = qpack_encode_literal_static_name(fs + fo, sizeof fs - fo,
                                              4, (const uint8_t*)clbuf, (size_t)cl);
        if (n == 0) return 0;
        fo += n;
    }

    /* Now emit HEADERS frame: type=1, len=fo, then payload. */
    size_t off = 0;
    n = h3_frame_encode(out + off, cap - off, H3_FT_HEADERS, fs, fo);
    if (n == 0) return 0;
    off += n;

    if (body) {
        n = h3_frame_encode(out + off, cap - off, H3_FT_DATA, body, body_len);
        if (n == 0) return 0;
        off += n;
    }
    return off;
}
