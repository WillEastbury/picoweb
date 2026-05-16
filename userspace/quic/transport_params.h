/*
 * QUIC transport parameters (RFC 9000 §18).
 *
 * Carried inside the TLS 1.3 EncryptedExtensions / ClientHello via
 * extension codepoint 0x39 (RFC 9001 §8.2). Each parameter is a
 * (varint id, varint len, value) tuple; unknown ids MUST be ignored.
 *
 * This module is pure data — encode to / decode from a contiguous
 * byte run. The caller is responsible for handing the encoded blob
 * to the TLS extension layer.
 */
#ifndef PICOWEB_USERSPACE_QUIC_TRANSPORT_PARAMS_H
#define PICOWEB_USERSPACE_QUIC_TRANSPORT_PARAMS_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_TP_MAX_CID_LEN              20
#define QUIC_TP_STATELESS_RESET_TOKEN_LEN 16

/* RFC 9000 §18.2 codepoints. */
typedef enum {
    QUIC_TP_ORIGINAL_DCID                 = 0x00,
    QUIC_TP_MAX_IDLE_TIMEOUT              = 0x01,
    QUIC_TP_STATELESS_RESET_TOKEN         = 0x02,
    QUIC_TP_MAX_UDP_PAYLOAD_SIZE          = 0x03,
    QUIC_TP_INITIAL_MAX_DATA              = 0x04,
    QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  = 0x05,
    QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06,
    QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI         = 0x07,
    QUIC_TP_INITIAL_MAX_STREAMS_BIDI      = 0x08,
    QUIC_TP_INITIAL_MAX_STREAMS_UNI       = 0x09,
    QUIC_TP_ACK_DELAY_EXPONENT            = 0x0a,
    QUIC_TP_MAX_ACK_DELAY                 = 0x0b,
    QUIC_TP_DISABLE_ACTIVE_MIGRATION      = 0x0c,
    QUIC_TP_PREFERRED_ADDRESS             = 0x0d,
    QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT    = 0x0e,
    QUIC_TP_INITIAL_SOURCE_CID            = 0x0f,
    QUIC_TP_RETRY_SOURCE_CID              = 0x10,
} quic_tp_id_t;

/* Bitmask of which TPs are present in a struct. */
enum {
    QUIC_TP_F_ORIGINAL_DCID                 = 1u <<  0,
    QUIC_TP_F_MAX_IDLE_TIMEOUT              = 1u <<  1,
    QUIC_TP_F_STATELESS_RESET_TOKEN         = 1u <<  2,
    QUIC_TP_F_MAX_UDP_PAYLOAD_SIZE          = 1u <<  3,
    QUIC_TP_F_INITIAL_MAX_DATA              = 1u <<  4,
    QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  = 1u <<  5,
    QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 1u <<  6,
    QUIC_TP_F_INITIAL_MAX_STREAM_DATA_UNI         = 1u <<  7,
    QUIC_TP_F_INITIAL_MAX_STREAMS_BIDI      = 1u <<  8,
    QUIC_TP_F_INITIAL_MAX_STREAMS_UNI       = 1u <<  9,
    QUIC_TP_F_ACK_DELAY_EXPONENT            = 1u << 10,
    QUIC_TP_F_MAX_ACK_DELAY                 = 1u << 11,
    QUIC_TP_F_DISABLE_ACTIVE_MIGRATION      = 1u << 12,
    QUIC_TP_F_ACTIVE_CONNECTION_ID_LIMIT    = 1u << 13,
    QUIC_TP_F_INITIAL_SOURCE_CID            = 1u << 14,
    QUIC_TP_F_RETRY_SOURCE_CID              = 1u << 15,
};

typedef struct {
    uint32_t present;          /* bitmask of QUIC_TP_F_* */

    uint8_t  original_dcid[QUIC_TP_MAX_CID_LEN];
    uint8_t  original_dcid_len;

    uint64_t max_idle_timeout_ms;

    uint8_t  stateless_reset_token[QUIC_TP_STATELESS_RESET_TOKEN_LEN];

    uint64_t max_udp_payload_size;       /* min 1200, default 65527 */
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;   /* max 2^60 */
    uint64_t initial_max_streams_uni;    /* max 2^60 */
    uint64_t ack_delay_exponent;         /* default 3, max 20 */
    uint64_t max_ack_delay_ms;           /* default 25, max < 2^14 */
    uint64_t active_connection_id_limit; /* min 2, default 2 */

    uint8_t  initial_source_cid[QUIC_TP_MAX_CID_LEN];
    uint8_t  initial_source_cid_len;

    uint8_t  retry_source_cid[QUIC_TP_MAX_CID_LEN];
    uint8_t  retry_source_cid_len;
} quic_transport_params_t;

/* Initialise `tp` to defaults from RFC 9000 §18.2; clears `present`.
 * Does NOT mark defaulted fields present — only fields the caller
 * explicitly sets and ORs into `present` will be encoded. */
void quic_tp_init_defaults(quic_transport_params_t* tp);

/* Encode `tp` into `out` (capacity `out_cap`). Returns bytes written
 * on success, or 0 on overflow / invalid value (e.g. cid_len > 20,
 * varint > 2^62-1, max_udp_payload_size < 1200, ack_delay_exponent
 * > 20, max_ack_delay_ms >= 2^14, active_cid_limit < 2). */
size_t quic_tp_encode(const quic_transport_params_t* tp,
                      uint8_t* out, size_t out_cap);

/* Decode transport params from `in`. Returns 1 on success and
 * populates `*tp` with defaults applied for absent params; 0 on
 * malformed input (truncated TLV, value oversized for declared
 * length, illegal value per §18.2). Unknown ids are skipped per
 * RFC 9000 §7.4. Duplicate ids are rejected (§7.4.2). */
int quic_tp_decode(const uint8_t* in, size_t in_len,
                   quic_transport_params_t* tp);

#endif
