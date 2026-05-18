/* QUIC STREAM rx — see stream.h. */
#include "stream.h"
#include <string.h>

void quic_stream_rx_init(quic_stream_rx_t* s, uint64_t stream_id)
{
    if (!s) return;
    memset(s, 0, sizeof *s);
    s->in_use    = 1;
    s->stream_id = stream_id;
    quic_crypto_rx_init(&s->rx, s->data, sizeof s->data,
                        s->bitmap, sizeof s->bitmap);
}

void quic_stream_rx_clear(quic_stream_rx_t* s)
{
    if (!s) return;
    memset(s, 0, sizeof *s);
}

int quic_stream_rx_ingest(quic_stream_rx_t* s,
                          uint64_t offset,
                          const uint8_t* data, size_t len,
                          int fin)
{
    if (!s || !s->in_use) return -1;
    if (len > 0 && !data) return -1;

    /* Compute end offset; reject overflow. */
    if (offset + len < offset) return -1;
    uint64_t end = offset + len;

    /* If FIN was already seen, no byte may extend past final_size,
     * and a re-declared FIN must agree on final_size (RFC 9000 §4.5). */
    if (s->fin_seen) {
        if (end > s->final_size) return -1;
        if (fin && end != s->final_size) {
            /* peer declared a smaller final_size than previous FIN */
            return -1;
        }
    } else if (fin) {
        /* New FIN — final_size is end. Any prior staged byte beyond
         * end is a violation. */
        if (s->rx.highest > end) return -1;
        s->fin_seen   = 1;
        s->final_size = end;
    }

    /* Empty STREAM frame (len=0) is legal; just records FIN if set. */
    if (len == 0) return fin ? 1 : 0;

    int rc = quic_crypto_rx_stage(&s->rx, offset, data, len);
    return rc;
}

const uint8_t* quic_stream_rx_peek(const quic_stream_rx_t* s, size_t* out_len)
{
    if (!s || !s->in_use) { if (out_len) *out_len = 0; return NULL; }
    return quic_crypto_rx_peek(&s->rx, out_len);
}

void quic_stream_rx_advance(quic_stream_rx_t* s, size_t n)
{
    if (!s || !s->in_use) return;
    quic_crypto_rx_advance(&s->rx, n);
}

int quic_stream_rx_is_complete(const quic_stream_rx_t* s)
{
    if (!s || !s->in_use || !s->fin_seen) return 0;
    return s->rx.contig_len == s->final_size;
}
