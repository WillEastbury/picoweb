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

/* ---- Static Huffman codec (RFC 7541 Appendix B) -------------- */

/* Auto-generated from RFC 7541 Appendix B */
static const uint32_t HUFF_CODE[257] = {
    0x00001ff8u, 0x007fffd8u, 0x0fffffe2u, 0x0fffffe3u,
    0x0fffffe4u, 0x0fffffe5u, 0x0fffffe6u, 0x0fffffe7u,
    0x0fffffe8u, 0x00ffffeau, 0x3ffffffcu, 0x0fffffe9u,
    0x0fffffeau, 0x3ffffffdu, 0x0fffffebu, 0x0fffffecu,
    0x0fffffedu, 0x0fffffeeu, 0x0fffffefu, 0x0ffffff0u,
    0x0ffffff1u, 0x0ffffff2u, 0x3ffffffeu, 0x0ffffff3u,
    0x0ffffff4u, 0x0ffffff5u, 0x0ffffff6u, 0x0ffffff7u,
    0x0ffffff8u, 0x0ffffff9u, 0x0ffffffau, 0x0ffffffbu,
    0x00000014u, 0x000003f8u, 0x000003f9u, 0x00000ffau,
    0x00001ff9u, 0x00000015u, 0x000000f8u, 0x000007fau,
    0x000003fau, 0x000003fbu, 0x000000f9u, 0x000007fbu,
    0x000000fau, 0x00000016u, 0x00000017u, 0x00000018u,
    0x00000000u, 0x00000001u, 0x00000002u, 0x00000019u,
    0x0000001au, 0x0000001bu, 0x0000001cu, 0x0000001du,
    0x0000001eu, 0x0000001fu, 0x0000005cu, 0x000000fbu,
    0x00007ffcu, 0x00000020u, 0x00000ffbu, 0x000003fcu,
    0x00001ffau, 0x00000021u, 0x0000005du, 0x0000005eu,
    0x0000005fu, 0x00000060u, 0x00000061u, 0x00000062u,
    0x00000063u, 0x00000064u, 0x00000065u, 0x00000066u,
    0x00000067u, 0x00000068u, 0x00000069u, 0x0000006au,
    0x0000006bu, 0x0000006cu, 0x0000006du, 0x0000006eu,
    0x0000006fu, 0x00000070u, 0x00000071u, 0x00000072u,
    0x000000fcu, 0x00000073u, 0x000000fdu, 0x00001ffbu,
    0x0007fff0u, 0x00001ffcu, 0x00003ffcu, 0x00000022u,
    0x00007ffdu, 0x00000003u, 0x00000023u, 0x00000004u,
    0x00000024u, 0x00000005u, 0x00000025u, 0x00000026u,
    0x00000027u, 0x00000006u, 0x00000074u, 0x00000075u,
    0x00000028u, 0x00000029u, 0x0000002au, 0x00000007u,
    0x0000002bu, 0x00000076u, 0x0000002cu, 0x00000008u,
    0x00000009u, 0x0000002du, 0x00000077u, 0x00000078u,
    0x00000079u, 0x0000007au, 0x0000007bu, 0x00007ffeu,
    0x000007fcu, 0x00003ffdu, 0x00001ffdu, 0x0ffffffcu,
    0x000fffe6u, 0x003fffd2u, 0x000fffe7u, 0x000fffe8u,
    0x003fffd3u, 0x003fffd4u, 0x003fffd5u, 0x007fffd9u,
    0x003fffd6u, 0x007fffdau, 0x007fffdbu, 0x007fffdcu,
    0x007fffddu, 0x007fffdeu, 0x00ffffebu, 0x007fffdfu,
    0x00ffffecu, 0x00ffffedu, 0x003fffd7u, 0x007fffe0u,
    0x00ffffeeu, 0x007fffe1u, 0x007fffe2u, 0x007fffe3u,
    0x007fffe4u, 0x001fffdcu, 0x003fffd8u, 0x007fffe5u,
    0x003fffd9u, 0x007fffe6u, 0x007fffe7u, 0x00ffffefu,
    0x003fffdau, 0x001fffddu, 0x000fffe9u, 0x003fffdbu,
    0x003fffdcu, 0x007fffe8u, 0x007fffe9u, 0x001fffdeu,
    0x007fffeau, 0x003fffddu, 0x003fffdeu, 0x00fffff0u,
    0x001fffdfu, 0x003fffdfu, 0x007fffebu, 0x007fffecu,
    0x001fffe0u, 0x001fffe1u, 0x003fffe0u, 0x001fffe2u,
    0x007fffedu, 0x003fffe1u, 0x007fffeeu, 0x007fffefu,
    0x000fffeau, 0x003fffe2u, 0x003fffe3u, 0x003fffe4u,
    0x007ffff0u, 0x003fffe5u, 0x003fffe6u, 0x007ffff1u,
    0x03ffffe0u, 0x03ffffe1u, 0x000fffebu, 0x0007fff1u,
    0x003fffe7u, 0x007ffff2u, 0x003fffe8u, 0x01ffffecu,
    0x03ffffe2u, 0x03ffffe3u, 0x03ffffe4u, 0x07ffffdeu,
    0x07ffffdfu, 0x03ffffe5u, 0x00fffff1u, 0x01ffffedu,
    0x0007fff2u, 0x001fffe3u, 0x03ffffe6u, 0x07ffffe0u,
    0x07ffffe1u, 0x03ffffe7u, 0x07ffffe2u, 0x00fffff2u,
    0x001fffe4u, 0x001fffe5u, 0x03ffffe8u, 0x03ffffe9u,
    0x0ffffffdu, 0x07ffffe3u, 0x07ffffe4u, 0x07ffffe5u,
    0x000fffecu, 0x00fffff3u, 0x000fffedu, 0x001fffe6u,
    0x003fffe9u, 0x001fffe7u, 0x001fffe8u, 0x007ffff3u,
    0x003fffeau, 0x003fffebu, 0x01ffffeeu, 0x01ffffefu,
    0x00fffff4u, 0x00fffff5u, 0x03ffffeau, 0x007ffff4u,
    0x03ffffebu, 0x07ffffe6u, 0x03ffffecu, 0x03ffffedu,
    0x07ffffe7u, 0x07ffffe8u, 0x07ffffe9u, 0x07ffffeau,
    0x07ffffebu, 0x0ffffffeu, 0x07ffffecu, 0x07ffffedu,
    0x07ffffeeu, 0x07ffffefu, 0x07fffff0u, 0x03ffffeeu,
    0x3fffffffu,
};
static const uint8_t HUFF_BITS[257] = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
     6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
     5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
    13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
     7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
    15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
     6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
};

size_t qpack_huffman_encoded_len(const uint8_t* in, size_t in_len)
{
    uint64_t bits = 0;
    for (size_t i = 0; i < in_len; ++i) bits += HUFF_BITS[in[i]];
    return (size_t)((bits + 7) / 8);
}

size_t qpack_huffman_encode(uint8_t* out, size_t cap,
                            const uint8_t* in, size_t in_len)
{
    if (!out || (!in && in_len)) return 0;
    /* Bit accumulator: hold up to 64 bits, MSB-first. */
    uint64_t acc = 0;
    int      acc_bits = 0;
    size_t   off = 0;
    for (size_t i = 0; i < in_len; ++i) {
        uint32_t code = HUFF_CODE[in[i]];
        int      nb   = HUFF_BITS[in[i]];
        acc = (acc << nb) | (uint64_t)code;
        acc_bits += nb;
        while (acc_bits >= 8) {
            if (off >= cap) return 0;
            acc_bits -= 8;
            out[off++] = (uint8_t)((acc >> acc_bits) & 0xff);
        }
    }
    if (acc_bits > 0) {
        /* Pad with EOS prefix (all 1s) up to byte boundary. */
        int pad = 8 - acc_bits;
        acc = (acc << pad) | (((uint64_t)1 << pad) - 1);
        if (off >= cap) return 0;
        out[off++] = (uint8_t)(acc & 0xff);
    }
    return off;
}

/* Decoder: lazy-init binary tree from (code,bits) table.
 *
 * Each node is uint16_t. High bit set ⇒ leaf, low 9 bits = symbol
 * (0..256). Otherwise low 15 bits = index of left child (right child
 * is left+1). Tree is built once from canonicalization-free table. */

#define HUFF_LEAF_BIT 0x8000u
#define HUFF_NODE_MAX 1024u

static uint16_t HUFF_TREE[HUFF_NODE_MAX * 2];
static uint16_t HUFF_TREE_USED;
static int      HUFF_TREE_INIT;

static uint16_t huff_alloc_node(void)
{
    /* Allocate two slots (left, right) and return base index. */
    uint16_t base = HUFF_TREE_USED;
    HUFF_TREE_USED = (uint16_t)(base + 2);
    HUFF_TREE[base] = 0; /* 0 = unfilled internal */
    HUFF_TREE[base + 1] = 0;
    return base;
}

static void huff_insert(uint16_t root, uint32_t code, int bits, uint16_t sym)
{
    uint16_t cur = root;
    for (int i = bits - 1; i > 0; --i) {
        int      b   = (code >> i) & 1;
        uint16_t pos = (uint16_t)(cur + b);
        if (HUFF_TREE[pos] == 0) {
            HUFF_TREE[pos] = huff_alloc_node();
        }
        cur = HUFF_TREE[pos];
    }
    int      b   = code & 1;
    uint16_t pos = (uint16_t)(cur + b);
    HUFF_TREE[pos] = (uint16_t)(HUFF_LEAF_BIT | sym);
}

static void huff_init(void)
{
    if (HUFF_TREE_INIT) return;
    HUFF_TREE_USED = 0;
    uint16_t root = huff_alloc_node(); /* base 0 */
    (void)root;
    for (int sym = 0; sym < 257; ++sym) {
        huff_insert(0, HUFF_CODE[sym], HUFF_BITS[sym], (uint16_t)sym);
    }
    HUFF_TREE_INIT = 1;
}

/* Returns bytes written, or (size_t)-1 on error. */
size_t qpack_huffman_decode(uint8_t* out, size_t cap,
                            const uint8_t* in, size_t in_len)
{
    huff_init();
    if (!out && cap) return (size_t)-1;
    if (!in && in_len) return (size_t)-1;
    uint16_t cur = 0;
    size_t   off = 0;
    int      bits_in_padding = 0;
    for (size_t i = 0; i < in_len; ++i) {
        uint8_t byte = in[i];
        for (int b = 7; b >= 0; --b) {
            int bit = (byte >> b) & 1;
            uint16_t nxt = HUFF_TREE[cur + bit];
            if (nxt == 0) return (size_t)-1; /* invalid path */
            if (nxt & HUFF_LEAF_BIT) {
                uint16_t sym = (uint16_t)(nxt & 0x1ff);
                if (sym == 256) return (size_t)-1; /* EOS forbidden */
                if (off >= cap) return (size_t)-2; /* overflow, not malformed */
                out[off++] = (uint8_t)sym;
                cur = 0;
                bits_in_padding = 0;
            } else {
                cur = nxt;
                bits_in_padding++;
            }
        }
    }
    /* RFC 7541 §5.2: any partial code at end must be a prefix of EOS
     * (all-1s) and at most 7 bits. */
    if (cur != 0) {
        if (bits_in_padding > 7) return (size_t)-1;
        /* Walk from cur: every step must go right (bit=1) and never
         * reach a leaf within these remaining bits. We've already
         * consumed bits_in_padding bits since last leaf; verify those
         * were all 1s by re-walking from root. Easier: track padding
         * value during decode. We didn't, so re-validate: any leaf
         * reachable from cur via all-1-path within (8 - bits_in_padding%8)
         * bits would have been consumed. Strict check: from cur, the
         * leftmost child (bit=0) must not be reachable as a valid
         * EOS prefix — i.e. require we've only walked right-children
         * from root. Re-check stored padding. */
        /* Simpler & spec-correct: if bits_in_padding ∈ [1..7], confirm
         * the final partial bits were all 1s by inspecting last input
         * byte. */
        size_t  last_i  = in_len - 1;
        uint8_t lastbyt = in[last_i];
        int     pad_bits = bits_in_padding; /* 1..7 */
        uint8_t pad_mask = (uint8_t)((1u << pad_bits) - 1);
        if ((lastbyt & pad_mask) != pad_mask) return (size_t)-1;
    }
    return off;
}

/* ---- Field-section decode with Huffman scratch buffer -------- */

static qpack_status_t decode_string_into(const uint8_t* in, size_t in_len,
                                         size_t* off_io,
                                         uint8_t* scratch, size_t scratch_cap,
                                         size_t* scratch_used_io,
                                         const uint8_t** out_ptr,
                                         size_t* out_len)
{
    size_t off = *off_io;
    if (off >= in_len) return QPACK_ERR_TRUNCATED;
    uint8_t b0 = in[off];
    int     huff = (b0 & 0x80) != 0;
    uint64_t slen;
    int      n = prefix_int_decode(in + off, in_len - off, 7, &slen);
    if (n == 0) return QPACK_ERR_TRUNCATED;
    if (n < 0)  return QPACK_ERR_BAD_VARINT;
    off += (size_t)n;
    if (slen > (uint64_t)(in_len - off)) return QPACK_ERR_TRUNCATED;
    if (!huff) {
        *out_ptr = slen ? (in + off) : NULL;
        *out_len = (size_t)slen;
        off += (size_t)slen;
        *off_io = off;
        return QPACK_OK;
    }
    /* Huffman: decode into scratch starting at scratch_used. */
    size_t used = *scratch_used_io;
    if (used > scratch_cap) return QPACK_ERR_OUTPUT_OVERFLOW;
    size_t avail = scratch_cap - used;
    size_t got = qpack_huffman_decode(scratch + used, avail,
                                      in + off, (size_t)slen);
    if (got == (size_t)-1) return QPACK_ERR_HUFFMAN;
    if (got == (size_t)-2) return QPACK_ERR_OUTPUT_OVERFLOW;
    *out_ptr = got ? (scratch + used) : NULL;
    *out_len = got;
    *scratch_used_io = used + got;
    off += (size_t)slen;
    *off_io = off;
    return QPACK_OK;
}

qpack_status_t qpack_decode_field_section_huff(const uint8_t* in, size_t in_len,
                                               qpack_field_t* out,
                                               size_t* out_count_in_out,
                                               uint8_t* scratch,
                                               size_t scratch_cap,
                                               size_t* scratch_used_out)
{
    if (!in || !out || !out_count_in_out)
        return QPACK_ERR_TRUNCATED;
    size_t cap = *out_count_in_out;
    *out_count_in_out = 0;
    if (scratch_used_out) *scratch_used_out = 0;
    size_t scratch_used = 0;

    int p = decode_prefix_static_only(in, in_len);
    if (p < 0) return (qpack_status_t)p;
    size_t off = (size_t)p;
    size_t count = 0;

    while (off < in_len) {
        if (count >= cap) return QPACK_ERR_OUTPUT_OVERFLOW;
        uint8_t b0 = in[off];
        qpack_field_t* f = &out[count];

        if (b0 & 0x80) {
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
            if ((b0 & 0x10) == 0) return QPACK_ERR_DYNAMIC_REQ;
            uint64_t idx;
            int n = prefix_int_decode(in + off, in_len - off, 4, &idx);
            if (n == 0) return QPACK_ERR_TRUNCATED;
            if (n < 0)  return QPACK_ERR_BAD_VARINT;
            off += (size_t)n;
            const char* nm; const char* vi; size_t nl, vli;
            if (qpack_static_get(idx, &nm, &nl, &vi, &vli) != 0)
                return QPACK_ERR_INDEX_OOR;
            f->name = (const uint8_t*)nm; f->name_len = nl;
            qpack_status_t s = decode_string_into(in, in_len, &off,
                                                  scratch, scratch_cap, &scratch_used,
                                                  &f->value, &f->value_len);
            if (s != QPACK_OK) return s;
        } else if (b0 & 0x20) {
            /* 001 N H name-len*(3) name value */
            int     huff_name = (b0 & 0x08) != 0;
            uint64_t nlen;
            int     nn = prefix_int_decode(in + off, in_len - off, 3, &nlen);
            if (nn == 0) return QPACK_ERR_TRUNCATED;
            if (nn < 0)  return QPACK_ERR_BAD_VARINT;
            off += (size_t)nn;
            if (nlen > (uint64_t)(in_len - off)) return QPACK_ERR_TRUNCATED;
            if (!huff_name) {
                f->name = nlen ? (in + off) : NULL;
                f->name_len = (size_t)nlen;
                off += (size_t)nlen;
            } else {
                size_t avail = scratch_cap - scratch_used;
                size_t got = qpack_huffman_decode(scratch + scratch_used,
                                                  avail, in + off, (size_t)nlen);
                if (got == (size_t)-1) return QPACK_ERR_HUFFMAN;
                if (got == (size_t)-2) return QPACK_ERR_OUTPUT_OVERFLOW;
                f->name = got ? (scratch + scratch_used) : NULL;
                f->name_len = got;
                scratch_used += got;
                off += (size_t)nlen;
            }
            qpack_status_t s = decode_string_into(in, in_len, &off,
                                                  scratch, scratch_cap, &scratch_used,
                                                  &f->value, &f->value_len);
            if (s != QPACK_OK) return s;
        } else {
            return QPACK_ERR_DYNAMIC_REQ;
        }
        count++;
    }

    *out_count_in_out = count;
    if (scratch_used_out) *scratch_used_out = scratch_used;
    return QPACK_OK;
}

/* ---- Huffman-emitting encoders (placed after Huffman codec) -- */

size_t qpack_encode_literal_static_name_huff(uint8_t* out, size_t cap,
                                             uint64_t name_index,
                                             const uint8_t* value, size_t value_len)
{
    if (name_index >= QPACK_STATIC_TABLE_SIZE) return 0;
    size_t off = prefix_int_encode(out, cap, 4, /*high*/ 0x70, name_index);
    if (off == 0) return 0;
    size_t hl = qpack_huffman_encoded_len(value, value_len);
    size_t v  = prefix_int_encode(out + off, cap - off, 7, /*high*/ 0x80, hl);
    if (v == 0) return 0;
    off += v;
    if (cap - off < hl) return 0;
    size_t w = qpack_huffman_encode(out + off, cap - off, value, value_len);
    if (w != hl) return 0;
    return off + w;
}

size_t qpack_encode_literal_huff(uint8_t* out, size_t cap,
                                 const uint8_t* name, size_t name_len,
                                 const uint8_t* value, size_t value_len)
{
    size_t hnl = qpack_huffman_encoded_len(name, name_len);
    size_t off = prefix_int_encode(out, cap, 3, /*high*/ 0x38, hnl);
    if (off == 0) return 0;
    if (cap - off < hnl) return 0;
    size_t wn = qpack_huffman_encode(out + off, cap - off, name, name_len);
    if (wn != hnl) return 0;
    off += wn;
    size_t hvl = qpack_huffman_encoded_len(value, value_len);
    size_t v   = prefix_int_encode(out + off, cap - off, 7, /*high*/ 0x80, hvl);
    if (v == 0) return 0;
    off += v;
    if (cap - off < hvl) return 0;
    size_t wv = qpack_huffman_encode(out + off, cap - off, value, value_len);
    if (wv != hvl) return 0;
    return off + wv;
}
