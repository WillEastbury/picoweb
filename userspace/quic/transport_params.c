#include "transport_params.h"
#include "varint.h"

#include <string.h>

void quic_tp_init_defaults(quic_transport_params_t* tp)
{
    memset(tp, 0, sizeof(*tp));
    tp->max_udp_payload_size       = 65527;
    tp->ack_delay_exponent         = 3;
    tp->max_ack_delay_ms           = 25;
    tp->active_connection_id_limit = 2;
}

/* --- encode helpers --- */

static int put_varint(uint8_t* out, size_t cap, size_t* off, uint64_t v)
{
    size_t n = quic_varint_encode(out + *off, cap - *off, v);
    if (n == 0) return 0;
    *off += n;
    return 1;
}

static int put_tlv_varint(uint8_t* out, size_t cap, size_t* off,
                          uint64_t id, uint64_t v)
{
    size_t vlen = quic_varint_size(v);
    if (!put_varint(out, cap, off, id)) return 0;
    if (!put_varint(out, cap, off, vlen)) return 0;
    if (cap - *off < vlen) return 0;
    size_t n = quic_varint_encode(out + *off, cap - *off, v);
    if (n != vlen) return 0;
    *off += n;
    return 1;
}

static int put_tlv_bytes(uint8_t* out, size_t cap, size_t* off,
                         uint64_t id, const uint8_t* p, size_t len)
{
    if (!put_varint(out, cap, off, id)) return 0;
    if (!put_varint(out, cap, off, len)) return 0;
    if (cap - *off < len) return 0;
    if (len) memcpy(out + *off, p, len);
    *off += len;
    return 1;
}

static int put_tlv_empty(uint8_t* out, size_t cap, size_t* off, uint64_t id)
{
    if (!put_varint(out, cap, off, id)) return 0;
    if (!put_varint(out, cap, off, 0)) return 0;
    return 1;
}

size_t quic_tp_encode(const quic_transport_params_t* tp,
                      uint8_t* out, size_t out_cap)
{
    /* Validation up front (§18.2). */
    if ((tp->present & QUIC_TP_F_MAX_UDP_PAYLOAD_SIZE) &&
        tp->max_udp_payload_size < 1200) return 0;
    if ((tp->present & QUIC_TP_F_ACK_DELAY_EXPONENT) &&
        tp->ack_delay_exponent > 20) return 0;
    if ((tp->present & QUIC_TP_F_MAX_ACK_DELAY) &&
        tp->max_ack_delay_ms >= (1u << 14)) return 0;
    if ((tp->present & QUIC_TP_F_ACTIVE_CONNECTION_ID_LIMIT) &&
        tp->active_connection_id_limit < 2) return 0;
    if ((tp->present & QUIC_TP_F_INITIAL_MAX_STREAMS_BIDI) &&
        tp->initial_max_streams_bidi > (UINT64_C(1) << 60)) return 0;
    if ((tp->present & QUIC_TP_F_INITIAL_MAX_STREAMS_UNI) &&
        tp->initial_max_streams_uni > (UINT64_C(1) << 60)) return 0;
    if ((tp->present & QUIC_TP_F_ORIGINAL_DCID) &&
        tp->original_dcid_len > QUIC_TP_MAX_CID_LEN) return 0;
    if ((tp->present & QUIC_TP_F_INITIAL_SOURCE_CID) &&
        tp->initial_source_cid_len > QUIC_TP_MAX_CID_LEN) return 0;
    if ((tp->present & QUIC_TP_F_RETRY_SOURCE_CID) &&
        tp->retry_source_cid_len > QUIC_TP_MAX_CID_LEN) return 0;

    size_t off = 0;

    if (tp->present & QUIC_TP_F_ORIGINAL_DCID)
        if (!put_tlv_bytes(out, out_cap, &off, QUIC_TP_ORIGINAL_DCID,
                           tp->original_dcid, tp->original_dcid_len)) return 0;
    if (tp->present & QUIC_TP_F_MAX_IDLE_TIMEOUT)
        if (!put_tlv_varint(out, out_cap, &off, QUIC_TP_MAX_IDLE_TIMEOUT,
                            tp->max_idle_timeout_ms)) return 0;
    if (tp->present & QUIC_TP_F_STATELESS_RESET_TOKEN)
        if (!put_tlv_bytes(out, out_cap, &off, QUIC_TP_STATELESS_RESET_TOKEN,
                           tp->stateless_reset_token,
                           QUIC_TP_STATELESS_RESET_TOKEN_LEN)) return 0;
    if (tp->present & QUIC_TP_F_MAX_UDP_PAYLOAD_SIZE)
        if (!put_tlv_varint(out, out_cap, &off, QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                            tp->max_udp_payload_size)) return 0;
    if (tp->present & QUIC_TP_F_INITIAL_MAX_DATA)
        if (!put_tlv_varint(out, out_cap, &off, QUIC_TP_INITIAL_MAX_DATA,
                            tp->initial_max_data)) return 0;
    if (tp->present & QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL)
        if (!put_tlv_varint(out, out_cap, &off,
                            QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                            tp->initial_max_stream_data_bidi_local)) return 0;
    if (tp->present & QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
        if (!put_tlv_varint(out, out_cap, &off,
                            QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                            tp->initial_max_stream_data_bidi_remote)) return 0;
    if (tp->present & QUIC_TP_F_INITIAL_MAX_STREAM_DATA_UNI)
        if (!put_tlv_varint(out, out_cap, &off,
                            QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                            tp->initial_max_stream_data_uni)) return 0;
    if (tp->present & QUIC_TP_F_INITIAL_MAX_STREAMS_BIDI)
        if (!put_tlv_varint(out, out_cap, &off,
                            QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                            tp->initial_max_streams_bidi)) return 0;
    if (tp->present & QUIC_TP_F_INITIAL_MAX_STREAMS_UNI)
        if (!put_tlv_varint(out, out_cap, &off,
                            QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                            tp->initial_max_streams_uni)) return 0;
    if (tp->present & QUIC_TP_F_ACK_DELAY_EXPONENT)
        if (!put_tlv_varint(out, out_cap, &off, QUIC_TP_ACK_DELAY_EXPONENT,
                            tp->ack_delay_exponent)) return 0;
    if (tp->present & QUIC_TP_F_MAX_ACK_DELAY)
        if (!put_tlv_varint(out, out_cap, &off, QUIC_TP_MAX_ACK_DELAY,
                            tp->max_ack_delay_ms)) return 0;
    if (tp->present & QUIC_TP_F_DISABLE_ACTIVE_MIGRATION)
        if (!put_tlv_empty(out, out_cap, &off,
                           QUIC_TP_DISABLE_ACTIVE_MIGRATION)) return 0;
    if (tp->present & QUIC_TP_F_ACTIVE_CONNECTION_ID_LIMIT)
        if (!put_tlv_varint(out, out_cap, &off,
                            QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                            tp->active_connection_id_limit)) return 0;
    if (tp->present & QUIC_TP_F_INITIAL_SOURCE_CID)
        if (!put_tlv_bytes(out, out_cap, &off, QUIC_TP_INITIAL_SOURCE_CID,
                           tp->initial_source_cid,
                           tp->initial_source_cid_len)) return 0;
    if (tp->present & QUIC_TP_F_RETRY_SOURCE_CID)
        if (!put_tlv_bytes(out, out_cap, &off, QUIC_TP_RETRY_SOURCE_CID,
                           tp->retry_source_cid,
                           tp->retry_source_cid_len)) return 0;

    return off;
}

/* --- decode --- */

/* Map TP id to its present-flag bit; returns 0 for unknown. */
static uint32_t tp_flag_for(uint64_t id)
{
    switch (id) {
    case QUIC_TP_ORIGINAL_DCID:                       return QUIC_TP_F_ORIGINAL_DCID;
    case QUIC_TP_MAX_IDLE_TIMEOUT:                    return QUIC_TP_F_MAX_IDLE_TIMEOUT;
    case QUIC_TP_STATELESS_RESET_TOKEN:               return QUIC_TP_F_STATELESS_RESET_TOKEN;
    case QUIC_TP_MAX_UDP_PAYLOAD_SIZE:                return QUIC_TP_F_MAX_UDP_PAYLOAD_SIZE;
    case QUIC_TP_INITIAL_MAX_DATA:                    return QUIC_TP_F_INITIAL_MAX_DATA;
    case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:  return QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL;
    case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: return QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE;
    case QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:         return QUIC_TP_F_INITIAL_MAX_STREAM_DATA_UNI;
    case QUIC_TP_INITIAL_MAX_STREAMS_BIDI:            return QUIC_TP_F_INITIAL_MAX_STREAMS_BIDI;
    case QUIC_TP_INITIAL_MAX_STREAMS_UNI:             return QUIC_TP_F_INITIAL_MAX_STREAMS_UNI;
    case QUIC_TP_ACK_DELAY_EXPONENT:                  return QUIC_TP_F_ACK_DELAY_EXPONENT;
    case QUIC_TP_MAX_ACK_DELAY:                       return QUIC_TP_F_MAX_ACK_DELAY;
    case QUIC_TP_DISABLE_ACTIVE_MIGRATION:            return QUIC_TP_F_DISABLE_ACTIVE_MIGRATION;
    case QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:          return QUIC_TP_F_ACTIVE_CONNECTION_ID_LIMIT;
    case QUIC_TP_INITIAL_SOURCE_CID:                  return QUIC_TP_F_INITIAL_SOURCE_CID;
    case QUIC_TP_RETRY_SOURCE_CID:                    return QUIC_TP_F_RETRY_SOURCE_CID;
    default: return 0;  /* unknown / preferred_address: not stored */
    }
}

/* Decode a varint that exactly consumes `len` bytes; reject any
 * shorter varint encoding that doesn't fit the declared length. */
static int decode_full_varint(const uint8_t* p, size_t len, uint64_t* out)
{
    uint64_t v = 0;
    size_t n = quic_varint_decode(p, len, &v);
    if (n != len) return 0;
    *out = v;
    return 1;
}

int quic_tp_decode(const uint8_t* in, size_t in_len,
                   quic_transport_params_t* tp)
{
    quic_tp_init_defaults(tp);
    tp->present = 0;

    size_t off = 0;
    while (off < in_len) {
        uint64_t id = 0, len = 0;
        size_t n = quic_varint_decode(in + off, in_len - off, &id);
        if (!n) return 0;
        off += n;
        n = quic_varint_decode(in + off, in_len - off, &len);
        if (!n) return 0;
        off += n;
        if (len > in_len - off) return 0;

        const uint8_t* val = in + off;
        off += len;

        uint32_t flag = tp_flag_for(id);
        if (!flag) {
            /* Unknown / preferred_address: skip per §7.4.
             * Preferred-address has 0x0d codepoint and a complex
             * structure we don't model in this phase; we ignore it
             * but still validate the TLV shape, which we already did. */
            continue;
        }

        if (tp->present & flag) return 0;  /* duplicate */

        switch (id) {
        case QUIC_TP_ORIGINAL_DCID:
        case QUIC_TP_INITIAL_SOURCE_CID:
        case QUIC_TP_RETRY_SOURCE_CID: {
            if (len > QUIC_TP_MAX_CID_LEN) return 0;
            uint8_t* dst;
            uint8_t* dlen;
            if (id == QUIC_TP_ORIGINAL_DCID) {
                dst = tp->original_dcid; dlen = &tp->original_dcid_len;
            } else if (id == QUIC_TP_INITIAL_SOURCE_CID) {
                dst = tp->initial_source_cid; dlen = &tp->initial_source_cid_len;
            } else {
                dst = tp->retry_source_cid; dlen = &tp->retry_source_cid_len;
            }
            if (len) memcpy(dst, val, len);
            *dlen = (uint8_t)len;
            break;
        }
        case QUIC_TP_STATELESS_RESET_TOKEN:
            if (len != QUIC_TP_STATELESS_RESET_TOKEN_LEN) return 0;
            memcpy(tp->stateless_reset_token, val, len);
            break;
        case QUIC_TP_DISABLE_ACTIVE_MIGRATION:
            if (len != 0) return 0;
            break;
        case QUIC_TP_MAX_IDLE_TIMEOUT:
            if (!decode_full_varint(val, len, &tp->max_idle_timeout_ms)) return 0;
            break;
        case QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
            if (!decode_full_varint(val, len, &tp->max_udp_payload_size)) return 0;
            if (tp->max_udp_payload_size < 1200) return 0;
            break;
        case QUIC_TP_INITIAL_MAX_DATA:
            if (!decode_full_varint(val, len, &tp->initial_max_data)) return 0;
            break;
        case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            if (!decode_full_varint(val, len, &tp->initial_max_stream_data_bidi_local)) return 0;
            break;
        case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            if (!decode_full_varint(val, len, &tp->initial_max_stream_data_bidi_remote)) return 0;
            break;
        case QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
            if (!decode_full_varint(val, len, &tp->initial_max_stream_data_uni)) return 0;
            break;
        case QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
            if (!decode_full_varint(val, len, &tp->initial_max_streams_bidi)) return 0;
            if (tp->initial_max_streams_bidi > (UINT64_C(1) << 60)) return 0;
            break;
        case QUIC_TP_INITIAL_MAX_STREAMS_UNI:
            if (!decode_full_varint(val, len, &tp->initial_max_streams_uni)) return 0;
            if (tp->initial_max_streams_uni > (UINT64_C(1) << 60)) return 0;
            break;
        case QUIC_TP_ACK_DELAY_EXPONENT:
            if (!decode_full_varint(val, len, &tp->ack_delay_exponent)) return 0;
            if (tp->ack_delay_exponent > 20) return 0;
            break;
        case QUIC_TP_MAX_ACK_DELAY:
            if (!decode_full_varint(val, len, &tp->max_ack_delay_ms)) return 0;
            if (tp->max_ack_delay_ms >= (1u << 14)) return 0;
            break;
        case QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
            if (!decode_full_varint(val, len, &tp->active_connection_id_limit)) return 0;
            if (tp->active_connection_id_limit < 2) return 0;
            break;
        default:
            return 0;  /* unreachable: tp_flag_for would have returned 0 */
        }

        tp->present |= flag;
    }

    return 1;
}
