/*
 * QPACK static table + decoder (RFC 9204).
 * See qpack.h for scope.
 */
#include "qpack.h"
#include "../quic/varint.h"

#include <string.h>

/* ---- Static table (RFC 9204 Appendix A) ---------------------- */

typedef struct { const char* name; const char* value; } qpack_static_entry_t;

static const qpack_static_entry_t k_static[QPACK_STATIC_TABLE_SIZE] = {
    /*  0 */ {":authority", ""},
    /*  1 */ {":path", "/"},
    /*  2 */ {"age", "0"},
    /*  3 */ {"content-disposition", ""},
    /*  4 */ {"content-length", "0"},
    /*  5 */ {"cookie", ""},
    /*  6 */ {"date", ""},
    /*  7 */ {"etag", ""},
    /*  8 */ {"if-modified-since", ""},
    /*  9 */ {"if-none-match", ""},
    /* 10 */ {"last-modified", ""},
    /* 11 */ {"link", ""},
    /* 12 */ {"location", ""},
    /* 13 */ {"referer", ""},
    /* 14 */ {"set-cookie", ""},
    /* 15 */ {":method", "CONNECT"},
    /* 16 */ {":method", "DELETE"},
    /* 17 */ {":method", "GET"},
    /* 18 */ {":method", "HEAD"},
    /* 19 */ {":method", "OPTIONS"},
    /* 20 */ {":method", "POST"},
    /* 21 */ {":method", "PUT"},
    /* 22 */ {":scheme", "http"},
    /* 23 */ {":scheme", "https"},
    /* 24 */ {":status", "103"},
    /* 25 */ {":status", "200"},
    /* 26 */ {":status", "304"},
    /* 27 */ {":status", "404"},
    /* 28 */ {":status", "503"},
    /* 29 */ {"accept", "*/*"},
    /* 30 */ {"accept", "application/dns-message"},
    /* 31 */ {"accept-encoding", "gzip, deflate, br"},
    /* 32 */ {"accept-ranges", "bytes"},
    /* 33 */ {"access-control-allow-headers", "cache-control"},
    /* 34 */ {"access-control-allow-headers", "content-type"},
    /* 35 */ {"access-control-allow-origin", "*"},
    /* 36 */ {"cache-control", "max-age=0"},
    /* 37 */ {"cache-control", "max-age=2592000"},
    /* 38 */ {"cache-control", "max-age=604800"},
    /* 39 */ {"cache-control", "no-cache"},
    /* 40 */ {"cache-control", "no-store"},
    /* 41 */ {"cache-control", "public, max-age=31536000"},
    /* 42 */ {"content-encoding", "br"},
    /* 43 */ {"content-encoding", "gzip"},
    /* 44 */ {"content-type", "application/dns-message"},
    /* 45 */ {"content-type", "application/javascript"},
    /* 46 */ {"content-type", "application/json"},
    /* 47 */ {"content-type", "application/x-www-form-urlencoded"},
    /* 48 */ {"content-type", "image/gif"},
    /* 49 */ {"content-type", "image/jpeg"},
    /* 50 */ {"content-type", "image/png"},
    /* 51 */ {"content-type", "text/css"},
    /* 52 */ {"content-type", "text/html; charset=utf-8"},
    /* 53 */ {"content-type", "text/plain"},
    /* 54 */ {"content-type", "text/plain;charset=utf-8"},
    /* 55 */ {"range", "bytes=0-"},
    /* 56 */ {"strict-transport-security", "max-age=31536000"},
    /* 57 */ {"strict-transport-security", "max-age=31536000; includesubdomains"},
    /* 58 */ {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
    /* 59 */ {"vary", "accept-encoding"},
    /* 60 */ {"vary", "origin"},
    /* 61 */ {"x-content-type-options", "nosniff"},
    /* 62 */ {"x-xss-protection", "1; mode=block"},
    /* 63 */ {":status", "100"},
    /* 64 */ {":status", "204"},
    /* 65 */ {":status", "206"},
    /* 66 */ {":status", "302"},
    /* 67 */ {":status", "400"},
    /* 68 */ {":status", "403"},
    /* 69 */ {":status", "421"},
    /* 70 */ {":status", "425"},
    /* 71 */ {":status", "500"},
    /* 72 */ {"accept-language", ""},
    /* 73 */ {"access-control-allow-credentials", "FALSE"},
    /* 74 */ {"access-control-allow-credentials", "TRUE"},
    /* 75 */ {"access-control-allow-headers", "*"},
    /* 76 */ {"access-control-allow-methods", "get"},
    /* 77 */ {"access-control-allow-methods", "get, post, options"},
    /* 78 */ {"access-control-allow-methods", "options"},
    /* 79 */ {"access-control-expose-headers", "content-length"},
    /* 80 */ {"access-control-request-headers", "content-type"},
    /* 81 */ {"access-control-request-method", "get"},
    /* 82 */ {"access-control-request-method", "post"},
    /* 83 */ {"alt-svc", "clear"},
    /* 84 */ {"authorization", ""},
    /* 85 */ {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
    /* 86 */ {"early-data", "1"},
    /* 87 */ {"expect-ct", ""},
    /* 88 */ {"forwarded", ""},
    /* 89 */ {"if-range", ""},
    /* 90 */ {"origin", ""},
    /* 91 */ {"purpose", "prefetch"},
    /* 92 */ {"server", ""},
    /* 93 */ {"timing-allow-origin", "*"},
    /* 94 */ {"upgrade-insecure-requests", "1"},
    /* 95 */ {"user-agent", ""},
    /* 96 */ {"x-forwarded-for", ""},
    /* 97 */ {"x-frame-options", "deny"},
    /* 98 */ {"x-frame-options", "sameorigin"},
};

int qpack_static_get(uint64_t index,
                     const char** out_name, size_t* out_name_len,
                     const char** out_value, size_t* out_value_len)
{
    if (index >= QPACK_STATIC_TABLE_SIZE) return -1;
    const qpack_static_entry_t* e = &k_static[index];
    if (out_name)      *out_name      = e->name;
    if (out_name_len)  *out_name_len  = strlen(e->name);
    if (out_value)     *out_value     = e->value;
    if (out_value_len) *out_value_len = strlen(e->value);
    return 0;
}

/* ---- N+ prefix integer (RFC 7541 §5.1) ----------------------- */

/* Decode an integer with an N-bit prefix. The first byte's low N bits
 * are the prefix; if all 1s, continue reading 7-bit groups with a
 * continuation bit until a byte with high bit clear.
 *
 *   in[0] high bits: caller's flags (we mask them off via prefix_mask).
 *
 * Returns bytes consumed, 0 on truncation, -1 on encoding error (>2^62
 * or > 8 continuation bytes). */
static int prefix_int_decode(const uint8_t* in, size_t in_len,
                             unsigned prefix_bits, uint64_t* out)
{
    if (in_len == 0) return 0;
    uint64_t mask = (1u << prefix_bits) - 1u;
    uint64_t v = in[0] & mask;
    if (v < mask) { *out = v; return 1; }

    /* Long form. */
    uint64_t m = 0;
    size_t off = 1;
    for (;;) {
        if (off >= in_len) return 0;
        uint8_t b = in[off++];
        v += ((uint64_t)(b & 0x7f)) << m;
        m += 7;
        if ((b & 0x80) == 0) { *out = v; return (int)off; }
        if (m > 56) return -1;  /* > 2^63 — never legitimate here */
    }
}

static size_t prefix_int_encode(uint8_t* out, size_t cap,
                                unsigned prefix_bits,
                                uint8_t high_bits,
                                uint64_t v)
{
    uint64_t mask = (1u << prefix_bits) - 1u;
    if (cap == 0) return 0;
    if (v < mask) {
        out[0] = (uint8_t)((high_bits & ~mask) | v);
        return 1;
    }
    out[0] = (uint8_t)((high_bits & ~mask) | mask);
    v -= mask;
    size_t off = 1;
    while (v >= 128) {
        if (off >= cap) return 0;
        out[off++] = (uint8_t)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    if (off >= cap) return 0;
    out[off++] = (uint8_t)v;
    return off;
}

/* ---- Field section prefix ----------------------------------- */

/* Decode the field-section prefix into a raw RIC/SignedDeltaBase pair.
 * For static-only we require both varints == 0. Returns bytes consumed
 * or negative error. */
static int decode_prefix_static_only(const uint8_t* in, size_t in_len)
{
    if (in_len < 2) return QPACK_ERR_TRUNCATED;
    uint64_t ric = 0, delta = 0;
    int n1 = prefix_int_decode(in, in_len, 8, &ric);
    if (n1 == 0) return QPACK_ERR_TRUNCATED;
    if (n1 < 0) return QPACK_ERR_BAD_VARINT;
    int n2 = prefix_int_decode(in + n1, in_len - n1, 7, &delta);
    if (n2 == 0) return QPACK_ERR_TRUNCATED;
    if (n2 < 0) return QPACK_ERR_BAD_VARINT;
    if (ric != 0)   return QPACK_ERR_DYNAMIC_REQ;
    if (delta != 0) return QPACK_ERR_DYNAMIC_REQ;
    return n1 + n2;
}

/* ---- Field section body decode ------------------------------ */

qpack_status_t qpack_decode_field_section(const uint8_t* in, size_t in_len,
                                          qpack_field_t* out,
                                          size_t* out_count_in_out)
{
    if (!in || !out || !out_count_in_out) return QPACK_ERR_TRUNCATED;
    size_t cap = *out_count_in_out;
    *out_count_in_out = 0;

    int p = decode_prefix_static_only(in, in_len);
    if (p < 0) return (qpack_status_t)p;
    size_t off = (size_t)p;
    size_t count = 0;

    while (off < in_len) {
        if (count >= cap) return QPACK_ERR_OUTPUT_OVERFLOW;
        uint8_t b0 = in[off];
        qpack_field_t* f = &out[count];

        if (b0 & 0x80) {
            /* Indexed Field Line: 1 T(=1) i*(6) — T=1 means static. */
            if ((b0 & 0x40) == 0) return QPACK_ERR_DYNAMIC_REQ;
            uint64_t idx;
            int n = prefix_int_decode(in + off, in_len - off, 6, &idx);
            if (n == 0) return QPACK_ERR_TRUNCATED;
            if (n < 0)  return QPACK_ERR_BAD_VARINT;
            const char* nm; const char* val; size_t nl, vl;
            if (qpack_static_get(idx, &nm, &nl, &val, &vl) != 0)
                return QPACK_ERR_INDEX_OOR;
            f->name = (const uint8_t*)nm; f->name_len = nl;
            f->value = (const uint8_t*)val; f->value_len = vl;
            off += (size_t)n;
        } else if (b0 & 0x40) {
            /* Literal Field Line With Name Reference: 01 N(1) T(1) i*(4)
             * Value follows: H(1) value-len*(7) value bytes. */
            if ((b0 & 0x10) == 0) return QPACK_ERR_DYNAMIC_REQ; /* T=0: dyn */
            uint64_t idx;
            int n = prefix_int_decode(in + off, in_len - off, 4, &idx);
            if (n == 0) return QPACK_ERR_TRUNCATED;
            if (n < 0)  return QPACK_ERR_BAD_VARINT;
            off += (size_t)n;
            const char* nm; const char* val_ignored; size_t nl, vl_ignored;
            if (qpack_static_get(idx, &nm, &nl, &val_ignored, &vl_ignored) != 0)
                return QPACK_ERR_INDEX_OOR;
            f->name = (const uint8_t*)nm; f->name_len = nl;

            if (off >= in_len) return QPACK_ERR_TRUNCATED;
            uint8_t vb0 = in[off];
            if (vb0 & 0x80) return QPACK_ERR_HUFFMAN;
            uint64_t vlen;
            int vn = prefix_int_decode(in + off, in_len - off, 7, &vlen);
            if (vn == 0) return QPACK_ERR_TRUNCATED;
            if (vn < 0)  return QPACK_ERR_BAD_VARINT;
            off += (size_t)vn;
            if (vlen > (uint64_t)(in_len - off)) return QPACK_ERR_TRUNCATED;
            f->value = vlen ? (in + off) : NULL;
            f->value_len = (size_t)vlen;
            off += (size_t)vlen;
        } else if (b0 & 0x20) {
            /* Literal Field Line With Literal Name: 001 N(1) H(1) name-len*(3)
             * then name bytes, then value as above. */
            if (b0 & 0x08) return QPACK_ERR_HUFFMAN; /* name H bit */
            uint64_t nlen;
            int nn = prefix_int_decode(in + off, in_len - off, 3, &nlen);
            if (nn == 0) return QPACK_ERR_TRUNCATED;
            if (nn < 0)  return QPACK_ERR_BAD_VARINT;
            off += (size_t)nn;
            if (nlen > (uint64_t)(in_len - off)) return QPACK_ERR_TRUNCATED;
            f->name = nlen ? (in + off) : NULL;
            f->name_len = (size_t)nlen;
            off += (size_t)nlen;

            if (off >= in_len) return QPACK_ERR_TRUNCATED;
            uint8_t vb0 = in[off];
            if (vb0 & 0x80) return QPACK_ERR_HUFFMAN;
            uint64_t vlen;
            int vn = prefix_int_decode(in + off, in_len - off, 7, &vlen);
            if (vn == 0) return QPACK_ERR_TRUNCATED;
            if (vn < 0)  return QPACK_ERR_BAD_VARINT;
            off += (size_t)vn;
            if (vlen > (uint64_t)(in_len - off)) return QPACK_ERR_TRUNCATED;
            f->value = vlen ? (in + off) : NULL;
            f->value_len = (size_t)vlen;
            off += (size_t)vlen;
        } else {
            /* 0001xxxx Indexed With Post-Base Index — dynamic only.
             * 0000xxxx Literal With Post-Base Name Ref  — dynamic only. */
            return QPACK_ERR_DYNAMIC_REQ;
        }

        count++;
    }

    *out_count_in_out = count;
    return QPACK_OK;
}

/* ---- Encoders --------------------------------------------- */

size_t qpack_encode_indexed_static(uint8_t* out, size_t cap, uint64_t index)
{
    if (index >= QPACK_STATIC_TABLE_SIZE) return 0;
    return prefix_int_encode(out, cap, 6, /*high*/ 0xc0, index);
}

size_t qpack_encode_literal_static_name(uint8_t* out, size_t cap,
                                        uint64_t name_index,
                                        const uint8_t* value, size_t value_len)
{
    if (name_index >= QPACK_STATIC_TABLE_SIZE) return 0;
    /* 01 1 1 i*(4) — N=1 (do not insert; we have no dyn table),
     * T=1 (static name). High bits = 0x70. */
    size_t off = prefix_int_encode(out, cap, 4, /*high*/ 0x70, name_index);
    if (off == 0) return 0;
    /* Value: H=0, len then bytes. */
    size_t v = prefix_int_encode(out + off, cap - off, 7, /*high*/ 0x00, value_len);
    if (v == 0) return 0;
    off += v;
    if (cap - off < value_len) return 0;
    if (value_len) memcpy(out + off, value, value_len);
    return off + value_len;
}

size_t qpack_encode_literal(uint8_t* out, size_t cap,
                            const uint8_t* name, size_t name_len,
                            const uint8_t* value, size_t value_len)
{
    /* 001 N(=1) H(=0) namelen*(3). High bits = 0x30. */
    size_t off = prefix_int_encode(out, cap, 3, /*high*/ 0x30, name_len);
    if (off == 0) return 0;
    if (cap - off < name_len) return 0;
    if (name_len) memcpy(out + off, name, name_len);
    off += name_len;
    size_t v = prefix_int_encode(out + off, cap - off, 7, /*high*/ 0x00, value_len);
    if (v == 0) return 0;
    off += v;
    if (cap - off < value_len) return 0;
    if (value_len) memcpy(out + off, value, value_len);
    return off + value_len;
}

size_t qpack_encode_prefix_empty(uint8_t* out, size_t cap)
{
    if (cap < 2) return 0;
    out[0] = 0;
    out[1] = 0;
    return 2;
}
