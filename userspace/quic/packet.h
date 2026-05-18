/*
 * QUIC long-header Initial packet build/parse + header protection.
 *
 * Scope: QUIC v1 Initial packets only (RFC 9000 §17.2.2 / RFC 9001).
 * Other long-header types (Handshake, 0-RTT, Retry) and the short-
 * header 1-RTT packet land in later phases.
 *
 * Build = unprotected header + frames-payload -> AEAD-seal -> header-
 *         protect -> wire bytes.
 * Parse = wire bytes -> header-deprotect -> AEAD-open -> unprotected
 *         header + frames-payload.
 */
#ifndef PICOWEB_USERSPACE_QUIC_PACKET_H
#define PICOWEB_USERSPACE_QUIC_PACKET_H

#include <stdint.h>
#include <stddef.h>

#include "initial.h"

#define QUIC_MAX_CID_LEN  20u
#define QUIC_MAX_TOKEN_LEN 256u

typedef struct {
    uint32_t version;                 /* QUIC v1 = 0x00000001 */
    uint8_t  dcid[QUIC_MAX_CID_LEN];
    size_t   dcid_len;
    uint8_t  scid[QUIC_MAX_CID_LEN];
    size_t   scid_len;
    /* Token is only present on client Initials (server-side Retry
     * tokens). Server Initials always have empty token. */
    uint8_t  token[QUIC_MAX_TOKEN_LEN];
    size_t   token_len;
    uint64_t pn;
    unsigned pn_len;                  /* 1..4 */
    const uint8_t* payload;           /* unprotected frames payload */
    size_t   payload_len;
} quic_initial_pkt_t;

/* Build a protected Initial packet (header-protected + AEAD-sealed)
 * into `out`. Caller must have populated `pkt` with all fields; the
 * payload is the plaintext frame bytes (e.g. CRYPTO+PADDING). Pads
 * payload up to a minimum total of 1200 bytes if `pad_to_min` is
 * non-zero (clients MUST do this, RFC 9000 §14.1).
 *
 * Returns total bytes written, or 0 on error. */
size_t quic_initial_build(uint8_t* out, size_t out_cap,
                          const quic_initial_pkt_t* pkt,
                          const quic_initial_keys_t* keys,
                          int pad_to_min);

/* Parse a protected Initial packet: remove header protection, decrypt
 * AEAD, populate `pkt`. The decrypted frame payload is written into
 * `scratch` and pkt->payload points into it.
 *
 * Returns 0 on success, -1 on parse/AEAD failure. */
int quic_initial_parse(const uint8_t* in, size_t in_len,
                       const quic_initial_keys_t* keys,
                       quic_initial_pkt_t* pkt,
                       uint8_t* scratch, size_t scratch_cap);

/* ---- Handshake long-header packets (RFC 9000 §17.2.4) ----------------
 *
 * Same wire shape as Initial except:
 *   - type bits in byte0 = 0b10 (Initial = 0b00)
 *   - no Token field
 *
 * Per RFC 9001 §5.1 the same key/iv/hp derivation procedure applies,
 * just driven from the handshake_traffic_secret (per direction)
 * instead of the initial_secret. We reuse `quic_initial_keys_t` as the
 * key bundle struct because the layouts are identical. */
typedef struct {
    uint32_t version;
    uint8_t  dcid[QUIC_MAX_CID_LEN];
    size_t   dcid_len;
    uint8_t  scid[QUIC_MAX_CID_LEN];
    size_t   scid_len;
    uint64_t pn;
    unsigned pn_len;                 /* 1..4 */
    const uint8_t* payload;
    size_t   payload_len;
} quic_handshake_pkt_t;

typedef quic_initial_keys_t quic_handshake_keys_t;

/* Build a protected Handshake packet. No padding/min-size logic —
 * Handshake packets are not subject to the 1200-byte minimum.
 * Returns total bytes written, or 0 on error. */
size_t quic_handshake_build(uint8_t* out, size_t out_cap,
                            const quic_handshake_pkt_t* pkt,
                            const quic_handshake_keys_t* keys);

/* Parse a protected Handshake packet. Returns 0 / -1 (same contract
 * as quic_initial_parse). */
int quic_handshake_parse(const uint8_t* in, size_t in_len,
                         const quic_handshake_keys_t* keys,
                         quic_handshake_pkt_t* pkt,
                         uint8_t* scratch, size_t scratch_cap);

#endif
