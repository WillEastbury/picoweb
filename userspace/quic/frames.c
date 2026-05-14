/*
 * QUIC v1 frame codec (RFC 9000 §19) — phase 4a.
 *
 * Pure varint-driven codec; no allocation. Decoders return views
 * into the caller's buffer to keep the hot path zero-copy.
 */
#include "frames.h"
#include "varint.h"

#include <string.h>
#include <stddef.h>

/* ---------------- decode helpers ---------------- */

static int read_varint(const uint8_t* in, size_t in_len,
                       size_t* off, uint64_t* v)
{
    if (*off >= in_len) return 0;
    size_t n = quic_varint_decode(in + *off, in_len - *off, v);
    if (n == 0) return 0;
    *off += n;
    return 1;
}

/* ---------------- decode ---------------- */

size_t quic_frame_decode(const uint8_t* in, size_t in_len, quic_frame_t* out)
{
    if (in_len == 0) return 0;

    memset(out, 0, sizeof(*out));
    size_t off = 0;
    uint8_t t = in[off++];
    out->raw_type = t;

    /* PADDING coalescing: report a run of 0x00 as a single frame. */
    if (t == 0x00) {
        size_t n = 1;
        while (off < in_len && in[off] == 0x00) { off++; n++; }
        out->type = QUIC_FT_PADDING;
        out->u.padding_count = n;
        return off;
    }

    if (t == 0x01) {
        out->type = QUIC_FT_PING;
        return off;
    }

    if (t == 0x1e) {
        out->type = QUIC_FT_HANDSHAKE_DONE;
        return off;
    }

    if (t == 0x02 || t == 0x03) {
        out->type = (t == 0x02) ? QUIC_FT_ACK : QUIC_FT_ACK_ECN;
        quic_frame_ack_t* a = &out->u.ack;
        if (!read_varint(in, in_len, &off, &a->largest))     return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &a->delay))       return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &a->range_count)) return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &a->first_range)) return QUIC_FRAME_DECODE_ERROR;
        /* Save raw range buffer — caller can iterate gap/range pairs. */
        a->ranges_buf = in + off;
        size_t ranges_start = off;
        for (uint64_t i = 0; i < a->range_count; i++) {
            uint64_t gap, len;
            if (!read_varint(in, in_len, &off, &gap)) return QUIC_FRAME_DECODE_ERROR;
            if (!read_varint(in, in_len, &off, &len)) return QUIC_FRAME_DECODE_ERROR;
        }
        a->ranges_len = off - ranges_start;
        if (t == 0x03) {
            a->has_ecn = 1;
            if (!read_varint(in, in_len, &off, &a->ect0)) return QUIC_FRAME_DECODE_ERROR;
            if (!read_varint(in, in_len, &off, &a->ect1)) return QUIC_FRAME_DECODE_ERROR;
            if (!read_varint(in, in_len, &off, &a->ce))   return QUIC_FRAME_DECODE_ERROR;
        }
        return off;
    }

    if (t == 0x06) {
        out->type = QUIC_FT_CRYPTO;
        quic_frame_crypto_t* c = &out->u.crypto;
        if (!read_varint(in, in_len, &off, &c->offset)) return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &c->length)) return QUIC_FRAME_DECODE_ERROR;
        if (c->length > in_len - off) return QUIC_FRAME_DECODE_ERROR;
        c->data = in + off;
        off += (size_t)c->length;
        return off;
    }

    if (t == 0x07) {
        out->type = QUIC_FT_NEW_TOKEN;
        quic_frame_new_token_t* nt = &out->u.new_token;
        if (!read_varint(in, in_len, &off, &nt->length)) return QUIC_FRAME_DECODE_ERROR;
        if (nt->length == 0) return QUIC_FRAME_DECODE_ERROR;  /* RFC 9000 §19.7 */
        if (nt->length > in_len - off) return QUIC_FRAME_DECODE_ERROR;
        nt->token = in + off;
        off += (size_t)nt->length;
        return off;
    }

    if (t >= 0x08 && t <= 0x0f) {
        out->type = QUIC_FT_STREAM;
        quic_frame_stream_t* s = &out->u.stream;
        int has_off = (t & 0x04) != 0;
        int has_len = (t & 0x02) != 0;
        s->fin = (t & 0x01) != 0;
        if (!read_varint(in, in_len, &off, &s->stream_id)) return QUIC_FRAME_DECODE_ERROR;
        if (has_off) {
            if (!read_varint(in, in_len, &off, &s->offset)) return QUIC_FRAME_DECODE_ERROR;
        }
        if (has_len) {
            if (!read_varint(in, in_len, &off, &s->length)) return QUIC_FRAME_DECODE_ERROR;
            if (s->length > in_len - off) return QUIC_FRAME_DECODE_ERROR;
        } else {
            s->length = in_len - off;
        }
        s->data = in + off;
        off += (size_t)s->length;
        return off;
    }

    if (t == 0x1c || t == 0x1d) {
        out->type = (t == 0x1c) ? QUIC_FT_CONNECTION_CLOSE
                                 : QUIC_FT_CONNECTION_CLOSE_A;
        quic_frame_close_t* c = &out->u.close;
        c->is_app = (t == 0x1d);
        if (!read_varint(in, in_len, &off, &c->error_code)) return QUIC_FRAME_DECODE_ERROR;
        if (!c->is_app) {
            if (!read_varint(in, in_len, &off, &c->frame_type)) return QUIC_FRAME_DECODE_ERROR;
        }
        if (!read_varint(in, in_len, &off, &c->reason_len)) return QUIC_FRAME_DECODE_ERROR;
        if (c->reason_len > in_len - off) return QUIC_FRAME_DECODE_ERROR;
        c->reason = (c->reason_len > 0) ? in + off : NULL;
        off += (size_t)c->reason_len;
        return off;
    }

    if (t == 0x04) {
        out->type = QUIC_FT_RESET_STREAM;
        quic_frame_reset_stream_t* r = &out->u.reset_stream;
        if (!read_varint(in, in_len, &off, &r->stream_id))      return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &r->app_error_code)) return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &r->final_size))     return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x05) {
        out->type = QUIC_FT_STOP_SENDING;
        quic_frame_stop_sending_t* s = &out->u.stop_sending;
        if (!read_varint(in, in_len, &off, &s->stream_id))      return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &s->app_error_code)) return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x10) {
        out->type = QUIC_FT_MAX_DATA;
        if (!read_varint(in, in_len, &off, &out->u.max_data.max)) return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x11) {
        out->type = QUIC_FT_MAX_STREAM_DATA;
        quic_frame_max_stream_data_t* m = &out->u.max_stream_data;
        if (!read_varint(in, in_len, &off, &m->stream_id)) return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &m->max))       return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x12 || t == 0x13) {
        out->type = (t == 0x12) ? QUIC_FT_MAX_STREAMS_BIDI : QUIC_FT_MAX_STREAMS_UNI;
        if (!read_varint(in, in_len, &off, &out->u.max_streams.max)) return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x14) {
        out->type = QUIC_FT_DATA_BLOCKED;
        if (!read_varint(in, in_len, &off, &out->u.data_blocked.limit)) return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x15) {
        out->type = QUIC_FT_STREAM_DATA_BLOCK;
        quic_frame_stream_data_blocked_t* b = &out->u.stream_data_blocked;
        if (!read_varint(in, in_len, &off, &b->stream_id)) return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &b->limit))     return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x16 || t == 0x17) {
        out->type = (t == 0x16) ? QUIC_FT_STREAMS_BLOCK_BIDI : QUIC_FT_STREAMS_BLOCK_UNI;
        if (!read_varint(in, in_len, &off, &out->u.streams_blocked.limit)) return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x18) {
        out->type = QUIC_FT_NEW_CONNECTION_ID;
        quic_frame_new_conn_id_t* n = &out->u.new_conn_id;
        if (!read_varint(in, in_len, &off, &n->seq_no))         return QUIC_FRAME_DECODE_ERROR;
        if (!read_varint(in, in_len, &off, &n->retire_prior_to)) return QUIC_FRAME_DECODE_ERROR;
        /* §19.15: retire_prior_to MUST be <= sequence number. */
        if (n->retire_prior_to > n->seq_no) return QUIC_FRAME_DECODE_ERROR;
        if (off >= in_len) return QUIC_FRAME_DECODE_ERROR;
        uint8_t cl = in[off++];
        /* §19.15: 1..20 inclusive. */
        if (cl < 1 || cl > 20) return QUIC_FRAME_DECODE_ERROR;
        if ((size_t)cl + 16 > in_len - off) return QUIC_FRAME_DECODE_ERROR;
        n->cid_len = cl;
        memcpy(n->cid, in + off, cl);
        off += cl;
        memcpy(n->stateless_reset_token, in + off, 16);
        off += 16;
        return off;
    }
    if (t == 0x19) {
        out->type = QUIC_FT_RETIRE_CONN_ID;
        if (!read_varint(in, in_len, &off, &out->u.retire_conn_id.seq_no)) return QUIC_FRAME_DECODE_ERROR;
        return off;
    }
    if (t == 0x1a || t == 0x1b) {
        out->type = (t == 0x1a) ? QUIC_FT_PATH_CHALLENGE : QUIC_FT_PATH_RESPONSE;
        if (in_len - off < 8) return QUIC_FRAME_DECODE_ERROR;
        memcpy(out->u.path.data, in + off, 8);
        off += 8;
        return off;
    }

    /* Unknown / unsupported. Caller decides whether to close with
     * FRAME_ENCODING_ERROR; we can't safely skip. */
    out->type = QUIC_FT_UNKNOWN;
    return off;
}

/* ---------------- encode helpers ---------------- */

static int put_varint(uint8_t* out, size_t cap, size_t* off, uint64_t v)
{
    if (*off > cap) return 0;
    size_t n = quic_varint_encode(out + *off, cap - *off, v);
    if (n == 0) return 0;
    *off += n;
    return 1;
}

static int put_u8(uint8_t* out, size_t cap, size_t* off, uint8_t v)
{
    if (*off >= cap) return 0;
    out[(*off)++] = v;
    return 1;
}

/* ---------------- encoders ---------------- */

size_t quic_frame_padding_encode(uint8_t* out, size_t cap, size_t n)
{
    if (n > cap) return 0;
    memset(out, 0x00, n);
    return n;
}

size_t quic_frame_ping_encode(uint8_t* out, size_t cap)
{
    if (cap < 1) return 0;
    out[0] = 0x01;
    return 1;
}

size_t quic_frame_handshake_done_encode(uint8_t* out, size_t cap)
{
    if (cap < 1) return 0;
    out[0] = 0x1e;
    return 1;
}

size_t quic_frame_crypto_encode(uint8_t* out, size_t cap,
                                uint64_t offset,
                                const uint8_t* data, size_t len)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x06)) return 0;
    if (!put_varint(out, cap, &off, offset)) return 0;
    if (!put_varint(out, cap, &off, (uint64_t)len)) return 0;
    if (len > cap - off) return 0;
    if (len > 0) memcpy(out + off, data, len);
    off += len;
    return off;
}

size_t quic_frame_ack_encode(uint8_t* out, size_t cap,
                             uint64_t largest, uint64_t delay,
                             uint64_t first_range)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x02)) return 0;
    if (!put_varint(out, cap, &off, largest)) return 0;
    if (!put_varint(out, cap, &off, delay)) return 0;
    if (!put_varint(out, cap, &off, 0)) return 0;          /* range count */
    if (!put_varint(out, cap, &off, first_range)) return 0;
    return off;
}

size_t quic_frame_stream_encode(uint8_t* out, size_t cap,
                                uint64_t stream_id, uint64_t offset,
                                const uint8_t* data, size_t len,
                                int fin)
{
    /* Always set OFF + LEN bits for predictable wire layout; callers
     * can coalesce with PADDING if they want. */
    uint8_t t = 0x08 | 0x04 | 0x02 | (fin ? 0x01 : 0x00);
    size_t off = 0;
    if (!put_u8(out, cap, &off, t)) return 0;
    if (!put_varint(out, cap, &off, stream_id)) return 0;
    if (!put_varint(out, cap, &off, offset)) return 0;
    if (!put_varint(out, cap, &off, (uint64_t)len)) return 0;
    if (len > cap - off) return 0;
    if (len > 0) memcpy(out + off, data, len);
    off += len;
    return off;
}

size_t quic_frame_close_encode(uint8_t* out, size_t cap,
                               int is_app,
                               uint64_t error_code,
                               uint64_t frame_type,
                               const uint8_t* reason, size_t reason_len)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, is_app ? 0x1d : 0x1c)) return 0;
    if (!put_varint(out, cap, &off, error_code)) return 0;
    if (!is_app) {
        if (!put_varint(out, cap, &off, frame_type)) return 0;
    }
    if (!put_varint(out, cap, &off, (uint64_t)reason_len)) return 0;
    if (reason_len > cap - off) return 0;
    if (reason_len > 0) memcpy(out + off, reason, reason_len);
    off += reason_len;
    return off;
}

size_t quic_frame_reset_stream_encode(uint8_t* out, size_t cap,
                                      uint64_t stream_id,
                                      uint64_t app_error_code,
                                      uint64_t final_size)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x04)) return 0;
    if (!put_varint(out, cap, &off, stream_id))      return 0;
    if (!put_varint(out, cap, &off, app_error_code)) return 0;
    if (!put_varint(out, cap, &off, final_size))     return 0;
    return off;
}

size_t quic_frame_stop_sending_encode(uint8_t* out, size_t cap,
                                      uint64_t stream_id,
                                      uint64_t app_error_code)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x05)) return 0;
    if (!put_varint(out, cap, &off, stream_id))      return 0;
    if (!put_varint(out, cap, &off, app_error_code)) return 0;
    return off;
}

size_t quic_frame_max_data_encode(uint8_t* out, size_t cap, uint64_t max)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x10)) return 0;
    if (!put_varint(out, cap, &off, max)) return 0;
    return off;
}

size_t quic_frame_max_stream_data_encode(uint8_t* out, size_t cap,
                                         uint64_t stream_id, uint64_t max)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x11)) return 0;
    if (!put_varint(out, cap, &off, stream_id)) return 0;
    if (!put_varint(out, cap, &off, max))       return 0;
    return off;
}

size_t quic_frame_max_streams_encode(uint8_t* out, size_t cap,
                                     int uni, uint64_t max)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, uni ? 0x13 : 0x12)) return 0;
    if (!put_varint(out, cap, &off, max)) return 0;
    return off;
}

size_t quic_frame_data_blocked_encode(uint8_t* out, size_t cap,
                                      uint64_t limit)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x14)) return 0;
    if (!put_varint(out, cap, &off, limit)) return 0;
    return off;
}

size_t quic_frame_stream_data_blocked_encode(uint8_t* out, size_t cap,
                                             uint64_t stream_id,
                                             uint64_t limit)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x15)) return 0;
    if (!put_varint(out, cap, &off, stream_id)) return 0;
    if (!put_varint(out, cap, &off, limit))     return 0;
    return off;
}

size_t quic_frame_streams_blocked_encode(uint8_t* out, size_t cap,
                                         int uni, uint64_t limit)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, uni ? 0x17 : 0x16)) return 0;
    if (!put_varint(out, cap, &off, limit)) return 0;
    return off;
}

size_t quic_frame_new_conn_id_encode(uint8_t* out, size_t cap,
                                     uint64_t seq_no,
                                     uint64_t retire_prior_to,
                                     const uint8_t* cid, size_t cid_len,
                                     const uint8_t* stateless_reset_token)
{
    if (cid_len < 1 || cid_len > 20) return 0;
    if (retire_prior_to > seq_no) return 0;
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x18)) return 0;
    if (!put_varint(out, cap, &off, seq_no))          return 0;
    if (!put_varint(out, cap, &off, retire_prior_to)) return 0;
    if (!put_u8(out, cap, &off, (uint8_t)cid_len))    return 0;
    if (cid_len + 16 > cap - off) return 0;
    memcpy(out + off, cid, cid_len);
    off += cid_len;
    if (stateless_reset_token) memcpy(out + off, stateless_reset_token, 16);
    else                       memset(out + off, 0, 16);
    off += 16;
    return off;
}

size_t quic_frame_retire_conn_id_encode(uint8_t* out, size_t cap,
                                        uint64_t seq_no)
{
    size_t off = 0;
    if (!put_u8(out, cap, &off, 0x19)) return 0;
    if (!put_varint(out, cap, &off, seq_no)) return 0;
    return off;
}

static size_t encode_path(uint8_t* out, size_t cap, uint8_t t,
                          const uint8_t data[8])
{
    if (cap < 9) return 0;
    out[0] = t;
    memcpy(out + 1, data, 8);
    return 9;
}

size_t quic_frame_path_challenge_encode(uint8_t* out, size_t cap,
                                        const uint8_t data[8])
{
    return encode_path(out, cap, 0x1a, data);
}

size_t quic_frame_path_response_encode(uint8_t* out, size_t cap,
                                       const uint8_t data[8])
{
    return encode_path(out, cap, 0x1b, data);
}
