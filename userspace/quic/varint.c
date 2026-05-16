/* QUIC variable-length integer (RFC 9000 §16). */
#include "varint.h"

size_t quic_varint_size(uint64_t v) {
    if (v <= 0x3f)               return 1;
    if (v <= 0x3fff)             return 2;
    if (v <= 0x3fffffff)         return 4;
    if (v <= QUIC_VARINT_MAX)    return 8;
    return 0;
}

size_t quic_varint_encode(uint8_t* out, size_t out_cap, uint64_t v) {
    size_t n = quic_varint_size(v);
    if (n == 0 || n > out_cap) return 0;
    switch (n) {
        case 1:
            out[0] = (uint8_t)v;            /* prefix 00 */
            break;
        case 2:
            out[0] = (uint8_t)(0x40 | ((v >> 8) & 0x3f));
            out[1] = (uint8_t)v;
            break;
        case 4:
            out[0] = (uint8_t)(0x80 | ((v >> 24) & 0x3f));
            out[1] = (uint8_t)(v >> 16);
            out[2] = (uint8_t)(v >>  8);
            out[3] = (uint8_t)v;
            break;
        case 8:
            out[0] = (uint8_t)(0xc0 | ((v >> 56) & 0x3f));
            out[1] = (uint8_t)(v >> 48);
            out[2] = (uint8_t)(v >> 40);
            out[3] = (uint8_t)(v >> 32);
            out[4] = (uint8_t)(v >> 24);
            out[5] = (uint8_t)(v >> 16);
            out[6] = (uint8_t)(v >>  8);
            out[7] = (uint8_t)v;
            break;
    }
    return n;
}

size_t quic_varint_decode(const uint8_t* in, size_t in_len, uint64_t* v) {
    if (in_len == 0) return 0;
    unsigned prefix = (in[0] >> 6) & 3u;
    size_t n = (size_t)1u << prefix;     /* 1, 2, 4, 8 */
    if (in_len < n) return 0;
    uint64_t x = (uint64_t)(in[0] & 0x3f);
    for (size_t i = 1; i < n; i++) {
        x = (x << 8) | in[i];
    }
    *v = x;
    return n;
}
