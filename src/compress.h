#ifndef METAL_COMPRESS_H
#define METAL_COMPRESS_H

/*
 * picoweb-compress: tiny block-based LZ77 compressor.
 *
 *   Wire-compatible with BareMetal.Compress (BareMetalWeb).
 *   Vendored into picoweb so we have NO third-party deps —
 *   the whole codec is one .c/.h pair, hand-written, MIT.
 *
 * Block format:
 *   [raw_len:u16 LE][comp_len:u16 LE][payload...]
 *   - raw_len  : uncompressed length of this block (bytes)
 *   - comp_len : payload length on the wire (bytes)
 *   - if raw_len == comp_len  → payload is stored verbatim (the
 *     encoder fell back because the LZ pass didn't help).
 *   - else                   → payload is LZ-encoded (see below).
 *
 * Token format inside an LZ-encoded block:
 *   - Literal run : [0 | run:7]            then `run` raw bytes      (run = 1..127)
 *   - Match       : [1 | (len-3):4 | offhi:3] [offlo:8]              (len = 3..18, off = 1..2047)
 *
 * Wire token used in HTTP:
 *   Accept-Encoding: picoweb-compress  (preferred)
 *   Accept-Encoding: BareMetal.Compress (legacy alias, also recognised)
 * Same on Content-Encoding when serving a compressed variant.
 *
 * The hot path is read-only after build: the encoder only runs at
 * startup (jumptable_build), the decoder lives client-side.
 *
 * Memory: ~512 B of stack for the per-block scratch buffer; the
 * compressor walks pointers, never allocates.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define METAL_COMP_BLOCK_SIZE 508
#define METAL_COMP_DICT_SIZE  2048   /* 11-bit window  -> matches offhi:3+offlo:8 = 2047 max */
#define METAL_COMP_MIN_MATCH  3
#define METAL_COMP_MAX_MATCH  18

/* Encode `input` into `output`. Returns bytes written, or -1 if
 * `output_cap` was too small. */
int    metal_compress(const uint8_t* input, size_t input_len,
                      uint8_t* output, size_t output_cap);

/* Decode (used only by tests; client-side decoder lives in JS). */
int    metal_decompress(const uint8_t* input, size_t input_len,
                        uint8_t* output, size_t output_cap);

/* Worst-case bound: every block stored verbatim + 4-byte header. */
size_t metal_compress_bound(size_t input_len);

/* True if the value of an Accept-Encoding header advertises a token
 * we serve. Tokens: "picoweb-compress", "BareMetal.Compress" (alias).
 * Substring scan; case-sensitive (these tokens are exact-form). */
bool   metal_compress_accepted(const char* accept_encoding, size_t len);

#endif
