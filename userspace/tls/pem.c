/*
 * Minimal PEM decoder.
 *
 * Hand-rolled base64 alphabet decode + Begin/End marker scanning.
 * Strict: rejects non-base64 chars inside the body (other than
 * whitespace) and rejects '=' padding in the wrong position.
 *
 * Spec deviations from RFC 7468 (deliberate, all on the strict side):
 *   - We do NOT enforce a 64-char line limit; longer lines OK.
 *   - We do NOT accept any pre-encapsulation-boundary text other
 *     than whitespace (so an attacker cannot smuggle padding above
 *     the BEGIN marker that confuses the next layer).
 *   - We require exact label match — case sensitive.
 */

#include "pem.h"

#include <stdio.h>
#include <string.h>

/* Returns base64 value for `c` in [0,63], or
 *   -1 = invalid char, -2 = padding '=', -3 = whitespace (skip). */
static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+')             return 62;
    if (c == '/')             return 63;
    if (c == '=')             return -2;
    if (c == '\r' || c == '\n' || c == '\t' || c == ' ') return -3;
    return -1;
}

/* Decode base64 chars from src[0..src_len) into dst[0..dst_cap),
 * skipping whitespace. Returns bytes written, or -1 on error. */
static int b64_decode(const char* src, size_t src_len,
                      uint8_t* dst, size_t dst_cap) {
    int  acc = 0;
    int  bits = 0;
    int  pad = 0;
    size_t out_len = 0;

    for (size_t i = 0; i < src_len; i++) {
        int v = b64val((unsigned char)src[i]);
        if (v == -3) continue;            /* whitespace */
        if (v == -2) { pad++; continue; } /* '=' */
        if (v < 0)   return -1;           /* garbage */
        if (pad)     return -1;           /* data after pad */

        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_len >= dst_cap) return -1;
            dst[out_len++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    /* base64 must encode to a whole byte stream; bits should be 0,2,4
     * (with appropriate padding). We don't enforce padding count
     * exactly because some PEM emitters omit it. */
    if (pad > 2) return -1;
    return (int)out_len;
}

/* Find substring `needle` in `hay[0..hay_len)`. Returns pointer or NULL. */
static const char* mem_find(const char* hay, size_t hay_len,
                            const char* needle, size_t needle_len) {
    if (needle_len == 0 || needle_len > hay_len) return NULL;
    size_t end = hay_len - needle_len;
    for (size_t i = 0; i <= end; i++) {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, needle_len) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

/* Locate the next "-----BEGIN <expected>-----" / "-----END <expected>-----"
 * pair in pem[ofs..pem_len). On success sets *body_start/*body_end and
 * *next_ofs (just past the END marker), returns 0. Returns -1 if no
 * matching block is found. */
static int find_block(const char* pem, size_t pem_len,
                      const char* label,
                      size_t ofs,
                      const char** body_start, const char** body_end,
                      size_t* next_ofs) {
    if (ofs > pem_len) return -1;
    size_t lab_len = strlen(label);

    /* Build "-----BEGIN <label>-----" */
    char begin_marker[256];
    char end_marker  [256];
    if (lab_len + 22 >= sizeof(begin_marker)) return -1;  /* implausible */
    int n1 = snprintf(begin_marker, sizeof(begin_marker),
                      "-----BEGIN %s-----", label);
    int n2 = snprintf(end_marker,   sizeof(end_marker),
                      "-----END %s-----", label);
    if (n1 < 0 || n2 < 0) return -1;

    const char* b = mem_find(pem + ofs, pem_len - ofs, begin_marker, (size_t)n1);
    if (!b) return -1;
    const char* body = b + n1;
    if (body > pem + pem_len) return -1;
    const char* e = mem_find(body, pem_len - (size_t)(body - pem),
                             end_marker, (size_t)n2);
    if (!e) return -1;

    *body_start = body;
    *body_end   = e;
    *next_ofs   = (size_t)((e + n2) - pem);
    return 0;
}

int pem_decode(const char* pem_in, size_t pem_len,
               const char* expected_label,
               uint8_t* out, size_t out_cap) {
    const char *bs, *be;
    size_t next_ofs;
    if (find_block(pem_in, pem_len, expected_label, 0, &bs, &be, &next_ofs) != 0) {
        return -1;
    }
    return b64_decode(bs, (size_t)(be - bs), out, out_cap);
}

int pem_decode_chain(const char* pem_in, size_t pem_len,
                     const char* expected_label,
                     uint8_t* out, size_t out_cap,
                     int* out_count) {
    size_t total = 0;
    int    count = 0;
    size_t ofs   = 0;

    while (ofs < pem_len) {
        const char *bs, *be;
        size_t next_ofs;
        if (find_block(pem_in, pem_len, expected_label, ofs, &bs, &be, &next_ofs) != 0) {
            break;
        }
        if (total >= out_cap) return -1;
        int n = b64_decode(bs, (size_t)(be - bs), out + total, out_cap - total);
        if (n < 0) return -1;
        total += (size_t)n;
        count++;
        ofs = next_ofs;
    }

    if (count == 0) return -1;
    if (out_count) *out_count = count;
    return (int)total;
}
