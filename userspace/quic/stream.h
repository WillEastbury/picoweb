/*
 * QUIC STREAM rx state (RFC 9000 §2, §3.2, §19.8).
 *
 * Per-stream byte-oriented reassembly for inbound STREAM frames. A
 * stream carries a unidirectional byte sequence (in the bidi case,
 * each direction is its own byte sequence) which may arrive out of
 * order and whose final size is fixed by the FIN bit (or by
 * RESET_STREAM, not handled here yet).
 *
 * Storage is fully embedded — no allocator. Capacity is a small
 * per-connection upper bound (16 KiB) sufficient for HTTP/3 request
 * headers + small request bodies; larger transfers will land when
 * flow control + dynamic resizing are wired.
 */
#ifndef PICOWEB_USERSPACE_QUIC_STREAM_H
#define PICOWEB_USERSPACE_QUIC_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include "crypto_stream.h"

#define QUIC_STREAM_RX_CAP   16384u
#define QUIC_STREAM_BITMAP_CAP ((QUIC_STREAM_RX_CAP + 7u) / 8u)

typedef struct {
    int      in_use;
    uint64_t stream_id;
    int      fin_seen;
    uint64_t final_size;       /* valid iff fin_seen */
    quic_crypto_rx_t rx;       /* reuses the offset-keyed reassembler */
    uint8_t  data[QUIC_STREAM_RX_CAP];
    uint8_t  bitmap[QUIC_STREAM_BITMAP_CAP];
} quic_stream_rx_t;

void quic_stream_rx_init(quic_stream_rx_t* s, uint64_t stream_id);
void quic_stream_rx_clear(quic_stream_rx_t* s);

/* Ingest a STREAM frame's payload into this stream's reassembler.
 *  fin: non-zero if the frame's FIN bit is set.
 * Returns:
 *    1  newly-staged data (or FIN newly observed)
 *    0  duplicate / no new bytes
 *   -1  PROTOCOL_VIOLATION / FINAL_SIZE_ERROR / would-overflow.
 *
 * Errors per RFC 9000 §4.5 (FINAL_SIZE_ERROR if a peer changes the
 * declared final size or sends data past it) and §7.5 (overlap
 * conflict). Capacity overflow returns -1.
 */
int quic_stream_rx_ingest(quic_stream_rx_t* s,
                          uint64_t offset,
                          const uint8_t* data, size_t len,
                          int fin);

/* In-order readable run; returns NULL if no new bytes. */
const uint8_t* quic_stream_rx_peek(const quic_stream_rx_t* s, size_t* out_len);
void           quic_stream_rx_advance(quic_stream_rx_t* s, size_t n);

/* True iff FIN has been seen AND every byte through final_size has
 * arrived in-order (i.e. the application has the whole stream). */
int quic_stream_rx_is_complete(const quic_stream_rx_t* s);

#endif
