#ifndef METAL_BROTLI_H
#define METAL_BROTLI_H

/*
 * micro-brotli: minimal RFC 7932 encoder for picoweb.
 *
 * Produces valid Brotli streams decodable by any browser.
 * Uses LZ77 + Huffman coding in a single meta-block.
 * Falls back to uncompressed meta-blocks when LZ77 doesn't help.
 *
 * Encoder only — browsers provide the decoder.
 * Zero external dependencies.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Encode `input` into a valid Brotli stream in `output`.
 * Returns bytes written, or -1 on error. */
int brotli_encode(const uint8_t* input, size_t input_len,
                  uint8_t* output, size_t output_cap);

/* Worst-case output size. */
size_t brotli_bound(size_t input_len);

/* True if Accept-Encoding value contains the "br" token with q > 0. */
bool brotli_accepted(const char* accept_encoding, size_t len);

#endif
