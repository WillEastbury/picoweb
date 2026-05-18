/*
 * QUIC v1 frame codec (RFC 9000 §19).
 *
 * Phase 4a covers the frames a minimal server needs to complete a
 * handshake and serve a request:
 *   PADDING (0x00), PING (0x01), ACK (0x02 / 0x03 with ECN),
 *   CRYPTO (0x06), NEW_TOKEN (0x07), STREAM (0x08..0x0f),
 *   CONNECTION_CLOSE (0x1c transport / 0x1d application),
 *   HANDSHAKE_DONE (0x1e).
 *
 * Other frame types are reported as QUIC_FT_UNKNOWN with the raw
 * type id; callers can treat them as a soft error per RFC 9000 §12.4
 * (FRAME_ENCODING_ERROR) or skip ahead if they choose.
 */
#ifndef PICOWEB_USERSPACE_QUIC_FRAMES_H
#define PICOWEB_USERSPACE_QUIC_FRAMES_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    QUIC_FT_PADDING            = 0x00,
    QUIC_FT_PING               = 0x01,
    QUIC_FT_ACK                = 0x02,
    QUIC_FT_ACK_ECN            = 0x03,
    QUIC_FT_RESET_STREAM       = 0x04,
    QUIC_FT_STOP_SENDING       = 0x05,
    QUIC_FT_CRYPTO             = 0x06,
    QUIC_FT_NEW_TOKEN          = 0x07,
    QUIC_FT_STREAM             = 0x08,  /* base; low 3 bits = OFF|LEN|FIN */
    QUIC_FT_MAX_DATA           = 0x10,
    QUIC_FT_MAX_STREAM_DATA    = 0x11,
    QUIC_FT_MAX_STREAMS_BIDI   = 0x12,
    QUIC_FT_MAX_STREAMS_UNI    = 0x13,
    QUIC_FT_DATA_BLOCKED       = 0x14,
    QUIC_FT_STREAM_DATA_BLOCK  = 0x15,
    QUIC_FT_STREAMS_BLOCK_BIDI = 0x16,
    QUIC_FT_STREAMS_BLOCK_UNI  = 0x17,
    QUIC_FT_NEW_CONNECTION_ID  = 0x18,
    QUIC_FT_RETIRE_CONN_ID     = 0x19,
    QUIC_FT_PATH_CHALLENGE     = 0x1a,
    QUIC_FT_PATH_RESPONSE      = 0x1b,
    QUIC_FT_CONNECTION_CLOSE   = 0x1c,
    QUIC_FT_CONNECTION_CLOSE_A = 0x1d,
    QUIC_FT_HANDSHAKE_DONE     = 0x1e,
    QUIC_FT_UNKNOWN            = 0xff,
} quic_frame_type_t;

typedef struct {
    uint64_t largest;
    uint64_t delay;        /* raw, NOT yet scaled by ack_delay_exponent */
    uint64_t range_count;  /* additional ranges after the first */
    uint64_t first_range;
    const uint8_t* ranges_buf;  /* points inside input */
    size_t ranges_len;
    int has_ecn;
    uint64_t ect0, ect1, ce;
} quic_frame_ack_t;

typedef struct {
    uint64_t offset;
    uint64_t length;
    const uint8_t* data;
} quic_frame_crypto_t;

typedef struct {
    const uint8_t* token;
    uint64_t length;
} quic_frame_new_token_t;

typedef struct {
    uint64_t stream_id;
    uint64_t offset;       /* 0 if OFF bit not set */
    uint64_t length;       /* extends to end of packet if LEN bit not set */
    int fin;
    const uint8_t* data;
} quic_frame_stream_t;

typedef struct {
    int is_app;            /* 0=transport (0x1c), 1=application (0x1d) */
    uint64_t error_code;
    uint64_t frame_type;   /* 0 when is_app */
    uint64_t reason_len;
    const uint8_t* reason;
} quic_frame_close_t;

typedef struct {
    uint64_t stream_id;
    uint64_t app_error_code;
    uint64_t final_size;
} quic_frame_reset_stream_t;

typedef struct {
    uint64_t stream_id;
    uint64_t app_error_code;
} quic_frame_stop_sending_t;

typedef struct {
    uint64_t max;
} quic_frame_max_data_t;

typedef struct {
    uint64_t stream_id;
    uint64_t max;
} quic_frame_max_stream_data_t;

typedef struct {
    uint64_t max;          /* max stream count, not stream id */
} quic_frame_max_streams_t;

typedef struct {
    uint64_t limit;        /* the limit that triggered the BLOCKED */
} quic_frame_data_blocked_t;

typedef struct {
    uint64_t stream_id;
    uint64_t limit;
} quic_frame_stream_data_blocked_t;

typedef struct {
    uint64_t limit;
} quic_frame_streams_blocked_t;

typedef struct {
    uint64_t seq_no;
    uint64_t retire_prior_to;
    uint8_t  cid_len;          /* 1..20 per §19.15 */
    uint8_t  cid[20];
    uint8_t  stateless_reset_token[16];
} quic_frame_new_conn_id_t;

typedef struct {
    uint64_t seq_no;
} quic_frame_retire_conn_id_t;

typedef struct {
    uint8_t data[8];           /* PATH_CHALLENGE / PATH_RESPONSE payload */
} quic_frame_path_data_t;

typedef struct {
    quic_frame_type_t type;
    uint8_t raw_type;      /* original byte, useful for STREAM bit decoding */
    union {
        quic_frame_ack_t                 ack;
        quic_frame_crypto_t              crypto;
        quic_frame_new_token_t           new_token;
        quic_frame_stream_t              stream;
        quic_frame_close_t               close;
        quic_frame_reset_stream_t        reset_stream;
        quic_frame_stop_sending_t        stop_sending;
        quic_frame_max_data_t            max_data;
        quic_frame_max_stream_data_t     max_stream_data;
        quic_frame_max_streams_t         max_streams;
        quic_frame_data_blocked_t        data_blocked;
        quic_frame_stream_data_blocked_t stream_data_blocked;
        quic_frame_streams_blocked_t     streams_blocked;
        quic_frame_new_conn_id_t         new_conn_id;
        quic_frame_retire_conn_id_t      retire_conn_id;
        quic_frame_path_data_t           path;
        size_t                           padding_count;
    } u;
} quic_frame_t;

/* Decode a single frame from in[0..in_len). On success returns
 * bytes consumed and fills *out. Returns 0 if the buffer is empty.
 * Returns SIZE_MAX on a hard parse error (truncated varint, length
 * exceeds buffer, malformed STREAM/ACK fields, etc.). */
#define QUIC_FRAME_DECODE_ERROR ((size_t)-1)
size_t quic_frame_decode(const uint8_t* in, size_t in_len, quic_frame_t* out);

/* Encoders. Each returns bytes written or 0 on capacity error. */
size_t quic_frame_padding_encode(uint8_t* out, size_t cap, size_t n);
size_t quic_frame_ping_encode(uint8_t* out, size_t cap);
size_t quic_frame_handshake_done_encode(uint8_t* out, size_t cap);
size_t quic_frame_crypto_encode(uint8_t* out, size_t cap,
                                uint64_t offset,
                                const uint8_t* data, size_t len);
/* Single-range ACK: ACKs packets [largest-first_range, largest]. */
size_t quic_frame_ack_encode(uint8_t* out, size_t cap,
                             uint64_t largest, uint64_t delay,
                             uint64_t first_range);
size_t quic_frame_stream_encode(uint8_t* out, size_t cap,
                                uint64_t stream_id, uint64_t offset,
                                const uint8_t* data, size_t len,
                                int fin);
/* reason may be NULL; reason_len then must be 0. is_app selects 0x1d. */
size_t quic_frame_close_encode(uint8_t* out, size_t cap,
                               int is_app,
                               uint64_t error_code,
                               uint64_t frame_type,
                               const uint8_t* reason, size_t reason_len);

size_t quic_frame_reset_stream_encode(uint8_t* out, size_t cap,
                                      uint64_t stream_id,
                                      uint64_t app_error_code,
                                      uint64_t final_size);
size_t quic_frame_stop_sending_encode(uint8_t* out, size_t cap,
                                      uint64_t stream_id,
                                      uint64_t app_error_code);
size_t quic_frame_max_data_encode(uint8_t* out, size_t cap, uint64_t max);
size_t quic_frame_max_stream_data_encode(uint8_t* out, size_t cap,
                                         uint64_t stream_id, uint64_t max);
/* uni=0 ⇒ MAX_STREAMS bidi (0x12); uni=1 ⇒ uni (0x13). */
size_t quic_frame_max_streams_encode(uint8_t* out, size_t cap,
                                     int uni, uint64_t max);
size_t quic_frame_data_blocked_encode(uint8_t* out, size_t cap,
                                      uint64_t limit);
size_t quic_frame_stream_data_blocked_encode(uint8_t* out, size_t cap,
                                             uint64_t stream_id,
                                             uint64_t limit);
size_t quic_frame_streams_blocked_encode(uint8_t* out, size_t cap,
                                         int uni, uint64_t limit);
/* cid_len in 1..20. token is 16 bytes (NULL ⇒ all zeros). */
size_t quic_frame_new_conn_id_encode(uint8_t* out, size_t cap,
                                     uint64_t seq_no,
                                     uint64_t retire_prior_to,
                                     const uint8_t* cid, size_t cid_len,
                                     const uint8_t* stateless_reset_token);
size_t quic_frame_retire_conn_id_encode(uint8_t* out, size_t cap,
                                        uint64_t seq_no);
/* PATH_CHALLENGE (0x1a) / PATH_RESPONSE (0x1b). data is 8 bytes. */
size_t quic_frame_path_challenge_encode(uint8_t* out, size_t cap,
                                        const uint8_t data[8]);
size_t quic_frame_path_response_encode(uint8_t* out, size_t cap,
                                       const uint8_t data[8]);

#endif
