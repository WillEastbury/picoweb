/*
 * picoweb-compress: vendored, hand-written block-LZ codec.
 *
 * Wire-compatible with BareMetal.Compress (so the existing JS
 * decoder client-side just works against picoweb). Pure C,
 * no third-party libraries, no allocations on the hot path.
 *
 * Encoder is O(n*window) per block — fine for startup-time
 * pre-compression. The decoder is small and runs at memcpy speed.
 *
 * Note: dictionary window is 2048 bytes (11 bits, packed as 3+8 in
 * the match token). BareMetal.Compress originally documents 256 B
 * but the wire packs 3+8 = 11 bits of offset, so 2048 is safe and
 * gives meaningfully better ratios on text payloads. The decoder
 * just uses whatever offset is on the wire — both ends agree.
 */
#include "compress.h"

#include <string.h>

/* ---- Encoder -------------------------------------------------- */

static int compress_block(const uint8_t* in, size_t in_len,
                          uint8_t* out, size_t out_cap, size_t* out_len) {
    if (in_len == 0) { *out_len = 0; return 0; }

    size_t op = 0;
    size_t i  = 0;
    size_t lit_start = 0;

    /* Helper: flush pending literals [lit_start, i) into `out`. */
#define FLUSH_LITERALS()                                                    \
    do {                                                                    \
        size_t _lit = i - lit_start;                                        \
        size_t _src = lit_start;                                            \
        while (_lit > 0) {                                                  \
            size_t run = _lit > 127 ? 127 : _lit;                           \
            if (op + 1 + run > out_cap) return -1;                          \
            out[op++] = (uint8_t)run;          /* high bit = 0  → literal */ \
            memcpy(out + op, in + _src, run);                               \
            op   += run;                                                    \
            _src += run;                                                    \
            _lit -= run;                                                    \
        }                                                                   \
    } while (0)

    while (i < in_len) {
        /* Look for the longest match in the preceding window.
         * Naive scan — fine for short startup payloads. */
        int best_len = 0;
        int best_off = 0;
        size_t window_start = (i > METAL_COMP_DICT_SIZE)
                            ? (i - METAL_COMP_DICT_SIZE) : 0;
        for (size_t j = window_start; j < i; j++) {
            int mlen = 0;
            int max  = (int)METAL_COMP_MAX_MATCH;
            int rem  = (int)(in_len - i);
            if (max > rem) max = rem;
            while (mlen < max && in[j + mlen] == in[i + mlen]) mlen++;
            if (mlen >= (int)METAL_COMP_MIN_MATCH && mlen > best_len) {
                best_len = mlen;
                best_off = (int)(i - j);
                if (best_len == (int)METAL_COMP_MAX_MATCH) break;
            }
        }

        if (best_len >= (int)METAL_COMP_MIN_MATCH) {
            FLUSH_LITERALS();
            if (op + 2 > out_cap) return -1;
            uint8_t len_code = (uint8_t)(best_len - METAL_COMP_MIN_MATCH); /* 0..15 */
            out[op++] = (uint8_t)(0x80 | (len_code << 3) | ((best_off >> 8) & 0x07));
            out[op++] = (uint8_t)(best_off & 0xFF);
            i += (size_t)best_len;
            lit_start = i;
        } else {
            i++;
        }
    }

    FLUSH_LITERALS();
#undef FLUSH_LITERALS

    *out_len = op;
    return 0;
}

int metal_compress(const uint8_t* input, size_t input_len,
                   uint8_t* output, size_t output_cap) {
    size_t ip = 0, op = 0;
    while (ip < input_len) {
        size_t blk = input_len - ip;
        if (blk > METAL_COMP_BLOCK_SIZE) blk = METAL_COMP_BLOCK_SIZE;
        if (op + 4 > output_cap) return -1;

        uint8_t scratch[METAL_COMP_BLOCK_SIZE + 64];
        size_t  comp_len = 0;
        int rc = compress_block(input + ip, blk, scratch, sizeof(scratch), &comp_len);

        bool stored = (rc != 0) || (comp_len >= blk);
        size_t payload = stored ? blk : comp_len;
        if (op + 4 + payload > output_cap) return -1;

        uint16_t raw_le = (uint16_t)blk;
        uint16_t cmp_le = stored ? (uint16_t)blk : (uint16_t)comp_len;
        /* Little-endian writes — the JS decoder expects LE. */
        output[op++] = (uint8_t)(raw_le & 0xFF);
        output[op++] = (uint8_t)((raw_le >> 8) & 0xFF);
        output[op++] = (uint8_t)(cmp_le & 0xFF);
        output[op++] = (uint8_t)((cmp_le >> 8) & 0xFF);
        if (stored) memcpy(output + op, input + ip, blk);
        else        memcpy(output + op, scratch, comp_len);
        op += payload;
        ip += blk;
    }
    return (int)op;
}

/* ---- Decoder -------------------------------------------------- */

static int decompress_block(const uint8_t* in, size_t in_len,
                            uint8_t* out, size_t out_cap, size_t* out_len) {
    size_t ip = 0, op = 0;
    while (ip < in_len) {
        uint8_t tag = in[ip++];
        if (tag & 0x80) {
            if (ip >= in_len) return -1;
            int mlen = ((tag >> 3) & 0x0F) + (int)METAL_COMP_MIN_MATCH;
            int off  = ((tag & 0x07) << 8) | in[ip++];
            if (off == 0 || (size_t)off > op) return -1;
            if (op + (size_t)mlen > out_cap) return -1;
            for (int k = 0; k < mlen; k++) {
                out[op + k] = out[op - off + k];
            }
            op += (size_t)mlen;
        } else {
            size_t run = tag;
            if (run == 0) break;
            if (ip + run > in_len || op + run > out_cap) return -1;
            memcpy(out + op, in + ip, run);
            ip += run;
            op += run;
        }
    }
    *out_len = op;
    return 0;
}

int metal_decompress(const uint8_t* input, size_t input_len,
                     uint8_t* output, size_t output_cap) {
    size_t ip = 0, op = 0;
    while (ip + 4 <= input_len) {
        uint16_t raw = (uint16_t)(input[ip] | ((uint16_t)input[ip + 1] << 8));
        uint16_t cmp = (uint16_t)(input[ip + 2] | ((uint16_t)input[ip + 3] << 8));
        ip += 4;
        if (cmp == 0) return -1;
        if (ip + cmp > input_len) return -1;
        if (op + raw > output_cap) return -1;
        if (raw == cmp) {
            memcpy(output + op, input + ip, raw);
            op += raw;
        } else {
            size_t got = 0;
            if (decompress_block(input + ip, cmp,
                                 output + op, output_cap - op, &got) != 0) return -1;
            if (got != raw) return -1;
            op += got;
        }
        ip += cmp;
    }
    return (int)op;
}

size_t metal_compress_bound(size_t input_len) {
    size_t blocks = (input_len + METAL_COMP_BLOCK_SIZE - 1) / METAL_COMP_BLOCK_SIZE;
    if (blocks == 0) blocks = 1;
    return input_len + blocks * 4 + 64;
}

/* ---- Header parsing ------------------------------------------- */

bool metal_compress_accepted(const char* v, size_t len) {
    if (!v || len == 0) return false;
    static const char tok1[] = "picoweb-compress";
    static const char tok2[] = "BareMetal.Compress";
    const size_t n1 = sizeof(tok1) - 1;
    const size_t n2 = sizeof(tok2) - 1;
    if (len >= n1) {
        for (size_t i = 0; i + n1 <= len; i++) {
            if (memcmp(v + i, tok1, n1) == 0) return true;
        }
    }
    if (len >= n2) {
        for (size_t i = 0; i + n2 <= len; i++) {
            if (memcmp(v + i, tok2, n2) == 0) return true;
        }
    }
    return false;
}
