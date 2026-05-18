/*
 * QUIC CRYPTO-frame byte stream (RFC 9000 §19.6, §7).
 *
 * Each encryption level (initial, 0-RTT-N/A, handshake, 1-RTT) carries
 * a unidirectional reliable byte stream of TLS handshake bytes via
 * CRYPTO frames. CRYPTO frames are unordered and may arrive with
 * gaps; this module:
 *
 *   - rx side: stages out-of-order CRYPTO data into a contiguous
 *     buffer keyed by offset, exposes only the in-order prefix to
 *     the TLS layer, and rejects overflow / overlap-conflict.
 *   - tx side: tracks the next outgoing byte offset and slices a
 *     queue of pending TLS bytes into CRYPTO frames sized to a
 *     caller-supplied MTU budget.
 *
 * No allocation; storage is owned by the embedder via the
 * quic_crypto_buf_t descriptor.
 */
#ifndef PICOWEB_USERSPACE_QUIC_CRYPTO_STREAM_H
#define PICOWEB_USERSPACE_QUIC_CRYPTO_STREAM_H

#include <stdint.h>
#include <stddef.h>

/* RFC 9000 §19.6: CRYPTO offset is a varint, max 2^62-1. We don't
 * intend to ever push more than ~64KiB through a handshake epoch in
 * practice; the bounded buffer enforces that. */

typedef struct {
    uint8_t* data;          /* caller-owned storage */
    size_t   cap;           /* buffer capacity in bytes */
    size_t   contig_len;    /* in-order bytes available from data[0] */
    size_t   highest;       /* highest (offset+len) ever staged; <= cap */
    /* Bitmap of received bytes for gap tracking. One bit per byte;
     * sized to ceil(cap/8). Caller-owned, alongside data. */
    uint8_t* bitmap;
    size_t   bitmap_cap;    /* >= (cap + 7) / 8 */
    /* Read cursor — bytes already consumed by the TLS layer. */
    size_t   consumed;
} quic_crypto_rx_t;

typedef struct {
    /* Pending bytes the TLS layer has produced for this epoch but
     * we haven't packetised yet. Caller-owned ring/linear buffer. */
    const uint8_t* pending;
    size_t         pending_len;
    /* Next offset to assign to the first byte of `pending`. */
    uint64_t       next_offset;
} quic_crypto_tx_t;

/* Initialise rx. data/bitmap must be caller-owned with the indicated
 * capacities; bitmap_cap must be >= ceil(data_cap/8). */
void quic_crypto_rx_init(quic_crypto_rx_t* rx,
                         uint8_t* data, size_t data_cap,
                         uint8_t* bitmap, size_t bitmap_cap);

/* Stage a CRYPTO frame payload at `offset` of length `len`.
 * Returns:
 *    1  on success (newly-staged data, possibly extending contig_len)
 *    0  duplicate-only (all bytes were already received and identical)
 *   -1  permanent error: would exceed buffer capacity OR overlapping
 *       bytes do not match what was previously staged (CRYPTO_ERROR per
 *       RFC 9000 §7.5).
 *
 * After a successful call, `rx->contig_len - rx->consumed` is the
 * number of newly-readable bytes; consume them with quic_crypto_rx_read. */
int quic_crypto_rx_stage(quic_crypto_rx_t* rx,
                         uint64_t offset,
                         const uint8_t* payload, size_t len);

/* Returns pointer to the next unread in-order byte and writes the
 * available run length into *out_len. Returns NULL if no new bytes
 * are available. The caller must invoke quic_crypto_rx_advance()
 * before the next stage() to record consumption. */
const uint8_t* quic_crypto_rx_peek(const quic_crypto_rx_t* rx,
                                   size_t* out_len);

/* Mark `n` previously-peeked bytes as consumed. */
void quic_crypto_rx_advance(quic_crypto_rx_t* rx, size_t n);

/* tx side ----------------------------------------------------- */

void quic_crypto_tx_init(quic_crypto_tx_t* tx);

/* Replace the pending buffer (e.g. after appending TLS output). The
 * caller must keep `pending` alive until quic_crypto_tx_consume is
 * called for the chunks that referenced it. */
void quic_crypto_tx_set_pending(quic_crypto_tx_t* tx,
                                const uint8_t* pending, size_t pending_len);

/* Produce the next CRYPTO chunk to ship. `max_payload` is the
 * maximum CRYPTO frame *body* size (after the type+offset+length
 * varint header — caller computes that). On success returns 1, sets
 * *out_offset and *out_chunk to a slice of `pending`, and *out_len
 * to its length. Returns 0 if no pending data remains. The bytes are
 * NOT yet considered consumed: call quic_crypto_tx_consume after the
 * caller has framed the chunk. */
int quic_crypto_tx_next(const quic_crypto_tx_t* tx,
                        size_t max_payload,
                        uint64_t* out_offset,
                        const uint8_t** out_chunk,
                        size_t* out_len);

/* Mark `n` bytes as consumed off the front of pending and advance
 * next_offset by `n`. */
void quic_crypto_tx_consume(quic_crypto_tx_t* tx, size_t n);

#endif
