#include "crypto_stream.h"

#include <string.h>

/* --- bitmap helpers -------------------------------------------- */

static inline int bm_get(const uint8_t* bm, size_t i)
{
    return (bm[i >> 3] >> (i & 7)) & 1u;
}

static inline void bm_set(uint8_t* bm, size_t i)
{
    bm[i >> 3] |= (uint8_t)(1u << (i & 7));
}

/* --- rx -------------------------------------------------------- */

void quic_crypto_rx_init(quic_crypto_rx_t* rx,
                         uint8_t* data, size_t data_cap,
                         uint8_t* bitmap, size_t bitmap_cap)
{
    rx->data       = data;
    rx->cap        = data_cap;
    rx->contig_len = 0;
    rx->highest    = 0;
    rx->bitmap     = bitmap;
    rx->bitmap_cap = bitmap_cap;
    rx->consumed   = 0;
    if (bitmap_cap) memset(bitmap, 0, bitmap_cap);
}

int quic_crypto_rx_stage(quic_crypto_rx_t* rx,
                         uint64_t offset,
                         const uint8_t* payload, size_t len)
{
    if (len == 0) return 0;

    /* Bounds: offset + len must fit in our buffer. */
    if (offset > rx->cap || len > rx->cap - (size_t)offset) return -1;
    if (((size_t)offset + len + 7) / 8 > rx->bitmap_cap) return -1;

    size_t off = (size_t)offset;
    int saw_new = 0;

    for (size_t i = 0; i < len; i++) {
        size_t pos = off + i;
        if (bm_get(rx->bitmap, pos)) {
            if (rx->data[pos] != payload[i]) return -1; /* conflict */
        } else {
            rx->data[pos] = payload[i];
            bm_set(rx->bitmap, pos);
            saw_new = 1;
        }
    }

    if (off + len > rx->highest) rx->highest = off + len;

    /* Recompute contig_len by extending forward from current value. */
    while (rx->contig_len < rx->highest &&
           bm_get(rx->bitmap, rx->contig_len)) {
        rx->contig_len++;
    }

    return saw_new ? 1 : 0;
}

const uint8_t* quic_crypto_rx_peek(const quic_crypto_rx_t* rx,
                                   size_t* out_len)
{
    if (rx->consumed >= rx->contig_len) {
        *out_len = 0;
        return NULL;
    }
    *out_len = rx->contig_len - rx->consumed;
    return rx->data + rx->consumed;
}

void quic_crypto_rx_advance(quic_crypto_rx_t* rx, size_t n)
{
    if (n > rx->contig_len - rx->consumed) n = rx->contig_len - rx->consumed;
    rx->consumed += n;
}

/* --- tx -------------------------------------------------------- */

void quic_crypto_tx_init(quic_crypto_tx_t* tx)
{
    tx->pending     = NULL;
    tx->pending_len = 0;
    tx->next_offset = 0;
}

void quic_crypto_tx_set_pending(quic_crypto_tx_t* tx,
                                const uint8_t* pending, size_t pending_len)
{
    tx->pending     = pending;
    tx->pending_len = pending_len;
}

int quic_crypto_tx_next(const quic_crypto_tx_t* tx,
                        size_t max_payload,
                        uint64_t* out_offset,
                        const uint8_t** out_chunk,
                        size_t* out_len)
{
    if (tx->pending_len == 0 || max_payload == 0) return 0;
    size_t n = tx->pending_len < max_payload ? tx->pending_len : max_payload;
    *out_offset = tx->next_offset;
    *out_chunk  = tx->pending;
    *out_len    = n;
    return 1;
}

void quic_crypto_tx_consume(quic_crypto_tx_t* tx, size_t n)
{
    if (n > tx->pending_len) n = tx->pending_len;
    tx->pending     += n;
    tx->pending_len -= n;
    tx->next_offset += n;
}
