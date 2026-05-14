/*
 * QUIC connection state — wave 5 phase 5e1: Initial-epoch rx pump.
 *
 * This is the first piece of QUIC connection state. It owns:
 *   - the role (client / server)
 *   - the Initial-epoch packet-protection keys (derived from the DCID
 *     of the first Initial packet received)
 *   - the Initial-epoch CRYPTO rx byte stream (reassembled TLS
 *     handshake bytes ready to be fed to the TLS parser)
 *   - the peer's source connection ID (echoed in the SCID of incoming
 *     packets) — needed to address response packets
 *
 * The handshake-epoch and 1-RTT state, the tx side, the loss / CC
 * machinery, ack management, and the actual TLS parser glue are
 * subsequent phases (5e2..). This module is the input plumbing only.
 *
 * Allocation policy: zero. All buffers live inside the struct.
 */
#ifndef PICOWEB_USERSPACE_QUIC_CONN_H
#define PICOWEB_USERSPACE_QUIC_CONN_H

#include <stdint.h>
#include <stddef.h>

#include "initial.h"
#include "packet.h"
#include "crypto_stream.h"

#define QUIC_CONN_RX_CRYPTO_CAP  4096u   /* per-epoch reassembly buffer */

typedef enum {
    QUIC_ROLE_CLIENT = 0,
    QUIC_ROLE_SERVER = 1,
} quic_role_t;

typedef struct {
    quic_role_t role;

    /* Initial-epoch packet protection. Lazily derived on the first
     * recv (server) or first send (client) once we know the DCID. */
    int                  initial_keys_ready;
    quic_initial_keys_t  initial_keys;

    /* Peer's CIDs as observed on the wire. */
    uint8_t  peer_dcid[QUIC_MAX_CID_LEN];   /* dcid the peer addresses us with */
    size_t   peer_dcid_len;
    uint8_t  peer_scid[QUIC_MAX_CID_LEN];   /* peer's source CID (we address them with this) */
    size_t   peer_scid_len;
    int      peer_addrs_known;

    /* Initial-epoch CRYPTO rx byte stream. */
    quic_crypto_rx_t rx_initial;
    uint8_t          rx_initial_data[QUIC_CONN_RX_CRYPTO_CAP];
    uint8_t          rx_initial_bm  [(QUIC_CONN_RX_CRYPTO_CAP + 7) / 8];

    /* Counters (for tests / metrics; not yet used for ack generation). */
    uint64_t initial_pkts_rcvd;
    uint64_t initial_crypto_bytes_rcvd;
    uint64_t initial_ack_eliciting_rcvd;  /* CRYPTO/STREAM/etc seen */
} quic_conn_t;

/* Initialise a server-side connection state. Does not derive Initial
 * keys yet — those come from the first client Initial. */
void quic_conn_init_server(quic_conn_t* c);

/* Process one received Initial packet (raw datagram bytes — caller
 * has already de-multiplexed UDP).
 *
 * Behaviour:
 *   - On the very first Initial received (server), Initial keys are
 *     derived from pkt.dcid (RFC 9001 §5.2) and peer addressing CIDs
 *     are recorded.
 *   - Subsequent Initials must reuse the same DCID; if not, returns -1.
 *   - The packet is removed-of-HP, AEAD-decrypted; on failure -1.
 *   - Frames are walked: CRYPTO frames are pushed into rx_initial.
 *     PADDING/PING/ACK frames are accepted and skipped (full ACK
 *     processing is a later phase). Any unsupported frame in an
 *     Initial is rejected with -1 (RFC 9000 §17.2.2 forbids
 *     STREAM/HANDSHAKE_DONE/etc. in Initial packets).
 *   - On any CRYPTO_ERROR (overlap/conflict/overflow), returns -1.
 *
 * Returns 0 on success. After success, quic_conn_initial_rx_peek
 * exposes the in-order reassembled prefix. */
int quic_conn_recv_initial(quic_conn_t* c,
                           const uint8_t* datagram, size_t len);

/* Peek at the contiguous prefix of reassembled Initial-epoch TLS
 * handshake bytes that have NOT yet been consumed via _advance.
 * Returns NULL (and writes 0 to *out_len) if no new bytes. */
const uint8_t* quic_conn_initial_rx_peek(const quic_conn_t* c,
                                         size_t* out_len);

/* Mark `n` previously-peeked bytes as handed to the TLS layer. */
void quic_conn_initial_rx_advance(quic_conn_t* c, size_t n);

/* Test helper: also force-derive Initial keys from a known DCID
 * (used by tests where the embedder wants to pre-stage keys without
 * driving an actual packet through). Idempotent. */
void quic_conn_force_derive_initial_keys(quic_conn_t* c,
                                         const uint8_t* dcid, size_t dcid_len);

#endif
