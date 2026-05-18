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
#include "transport_params.h"
#include "../tls/handshake.h"

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

    /* ---- tx side (wave 5 phase 5e3) ---- */

    /* Initial-epoch packet protection for outbound packets. Same DCID
     * seed as `initial_keys` but derived with the opposite is_server
     * sense. Lazily derived once peer_dcid is known. */
    int                  initial_tx_keys_ready;
    quic_initial_keys_t  initial_tx_keys;

    /* Our chosen SCID — appears as the SCID in long-header packets we
     * emit, and as the DCID the peer uses to address us in subsequent
     * packets after the first server response. */
    uint8_t  our_scid[QUIC_MAX_CID_LEN];
    size_t   our_scid_len;

    /* Outbound CRYPTO byte stream + next packet number for Initial. */
    quic_crypto_tx_t tx_initial;
    uint64_t         initial_tx_next_pn;

    /* ---- Handshake epoch (wave 5 phase 5e5) ----
     *
     * Activated once the TLS engine has produced per-direction
     * handshake_traffic_secret values. Embedder calls
     * quic_conn_install_handshake_secrets to derive packet keys
     * (key/iv/hp via "quic key" / "quic iv" / "quic hp" labels —
     * RFC 9001 §5.1).
     */
    int                  handshake_keys_ready;
    quic_handshake_keys_t handshake_tx_keys;   /* server-encrypted (out) */
    quic_handshake_keys_t handshake_rx_keys;   /* client-encrypted (in)  */

    quic_crypto_rx_t rx_handshake;
    uint8_t          rx_handshake_data[QUIC_CONN_RX_CRYPTO_CAP];
    uint8_t          rx_handshake_bm  [(QUIC_CONN_RX_CRYPTO_CAP + 7) / 8];

    quic_crypto_tx_t tx_handshake;
    uint64_t         handshake_tx_next_pn;

    /* Counters. */
    uint64_t handshake_pkts_rcvd;
    uint64_t handshake_crypto_bytes_rcvd;
    uint64_t handshake_ack_eliciting_rcvd;

    /* ---- Handshake-secret persistence (wave 5 phase 5e6) ----
     *
     * Populated by quic_server_drive_handshake; consumed by phase 5e7
     * (client Finished verify + 1-RTT key derivation).
     */
    int     have_handshake_state;
    uint8_t handshake_secret               [32];
    uint8_t client_handshake_traffic_secret[32];
    uint8_t server_handshake_traffic_secret[32];
    /* Transcript hash (SHA-256) up to AND including the server
     * Finished — fed into tls13_compute_application_secrets to derive
     * 1-RTT traffic secrets in phase 5e7. */
    uint8_t transcript_hash_thru_server_fin[32];

    /* ---- Driver-owned scratch (wave 5 phase 5e6) ----
     *
     * The Initial / Handshake tx aliases REQUIRE the byte buffers to
     * outlive set_pending. The handshake driver writes its built
     * messages into these conn-resident arenas and points the tx
     * pipelines at them. Sized to comfortably fit a one-shot server
     * flight: SH < 200B; EE+Cert(ed25519 leaf, ~1 KB)+CV+Fin < 2 KB.
     */
#define QUIC_CONN_DRV_INITIAL_CAP   256u
#define QUIC_CONN_DRV_HANDSHAKE_CAP 8192u
    uint8_t drv_initial_blob   [QUIC_CONN_DRV_INITIAL_CAP];
    size_t  drv_initial_blob_len;
    uint8_t drv_handshake_blob [QUIC_CONN_DRV_HANDSHAKE_CAP];
    size_t  drv_handshake_blob_len;

    /* ---- 1-RTT (Application) epoch keys (wave 5 phase 5e7) ----
     *
     * Populated by quic_server_finish_handshake once the client
     * Finished has been verified. AES-128-GCM keys derived from
     * client/server_application_traffic_secret_0 via the standard
     * QUIC labels. The Initial-/Handshake-epoch keys are NOT
     * discarded here — RFC 9001 §4.9 retention is the embedder's
     * concern.
     */
    int                  app_keys_ready;
    quic_handshake_keys_t app_tx_keys;   /* server-encrypted to client */
    quic_handshake_keys_t app_rx_keys;   /* client-encrypted to server */
    uint8_t client_application_traffic_secret_0[32];
    uint8_t server_application_traffic_secret_0[32];
    uint8_t master_secret[32];
    uint64_t app_tx_next_pn;
    uint64_t app_pkts_rcvd;

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

/* Try to extract a complete ClientHello + the QUIC transport-parameters
 * extension from the Initial-epoch CRYPTO rx stream (wave 5 phase 5e2).
 *
 * Behaviour:
 *   - Peeks the contiguous in-order rx prefix.
 *   - If fewer bytes than a full TLS handshake message are buffered,
 *     returns 0 without modifying *parsed_out / *peer_tp_out (caller
 *     should pump more packets and retry).
 *   - On a complete CH:
 *       * Parses it via tls13_parse_client_hello (RFC 8446 §4.1.2).
 *       * Locates the QUIC transport_parameters extension (codepoint
 *         0x0039) inside the CH extensions block per RFC 9001 §8.2.
 *       * Decodes the TPs into *peer_tp_out per RFC 9000 §18.
 *     Returns 1 on full success.
 *   - Returns -1 on any of: CH parse failure, CH extensions block
 *     malformed, QUIC TP extension missing (REQUIRED in CH per
 *     RFC 9001 §8.2), TP decode failure.
 *
 * Note: parsed_out->raw aliases the conn's Initial rx buffer. It
 * remains valid until the caller calls quic_conn_initial_rx_advance.
 *
 * This call is idempotent and read-only on the conn — it does not
 * advance the rx cursor. The caller chooses when to advance after it
 * has driven the CH bytes into its TLS engine.
 */
int quic_conn_initial_extract_client_hello(const quic_conn_t* c,
                                           tls13_client_hello_t* parsed_out,
                                           quic_transport_params_t* peer_tp_out);

/* Test helper: also force-derive Initial keys from a known DCID
 * (used by tests where the embedder wants to pre-stage keys without
 * driving an actual packet through). Idempotent. */
void quic_conn_force_derive_initial_keys(quic_conn_t* c,
                                         const uint8_t* dcid, size_t dcid_len);

/* ---- tx side (wave 5 phase 5e3) -------------------------------------
 *
 * Outbound Initial-packet emission. The flow:
 *
 *   1. Embedder receives the first client Initial via
 *      quic_conn_recv_initial — that records peer_dcid / peer_scid.
 *   2. Embedder picks its own SCID (random or deterministic) and
 *      installs it via quic_conn_set_our_scid.
 *   3. TLS engine produces a server flight prefix (typically a
 *      ServerHello). Embedder hands the bytes to
 *      quic_conn_initial_tx_set_pending — an alias, not a copy; the
 *      memory must remain valid until the bytes have been emitted.
 *   4. Embedder calls quic_conn_emit_initial repeatedly until it
 *      returns 0 (no more pending bytes). Each call produces one
 *      protected Initial packet on the wire.
 *
 * Server-direction Initial keys are lazily derived from peer_dcid
 * (the same DCID seed used to derive the inbound keys, RFC 9001 §5.2)
 * with the opposite is_server sense.
 */

/* Install our SCID (the source connection id we put in long-header
 * packets we emit). May be 0..QUIC_MAX_CID_LEN bytes. */
void quic_conn_set_our_scid(quic_conn_t* c,
                            const uint8_t* scid, size_t scid_len);

/* Set the pending bytes to be emitted in CRYPTO frames during the
 * Initial epoch. Aliases (no copy) — the buffer must remain valid
 * for the lifetime of the emission. Resets the pending region; offsets
 * already consumed are NOT reset (that would re-send already-emitted
 * bytes with the wrong CRYPTO offset). */
void quic_conn_initial_tx_set_pending(quic_conn_t* c,
                                      const uint8_t* bytes, size_t len);

/* Emit one protected Initial packet.
 *
 * Builds: a single CRYPTO frame carrying the next chunk of pending
 * tx bytes, packed into a long-header Initial packet addressed to the
 * peer (DCID = peer_scid, SCID = our_scid), AEAD-sealed and header-
 * protected via the lazily-derived server-direction Initial keys.
 *
 * Pre-conditions:
 *   - peer addresses must be known (a prior quic_conn_recv_initial
 *     must have succeeded), and our_scid must have been installed.
 *
 * Returns the number of wire bytes written to `out` (>= 0). 0 means
 * either there are no pending bytes to send, out_cap is too small to
 * hold even a minimal packet, or pre-conditions are not met.
 *
 * Side effects on success:
 *   - tx_initial cursor is advanced by the chunk size emitted
 *   - initial_tx_next_pn is incremented
 *   - initial_tx_keys are derived if not yet ready
 */
size_t quic_conn_emit_initial(quic_conn_t* c,
                              uint8_t* out, size_t out_cap);

/* ---- Handshake epoch (wave 5 phase 5e5) ----------------------------- */

/* Install per-direction handshake-epoch traffic secrets (each is
 * `secret_len` bytes, typically 32 for SHA-256). Derives AES-128-GCM
 * key / IV / HP per RFC 9001 §5.1 using the "quic key" / "quic iv" /
 * "quic hp" labels. After this call, handshake_keys_ready becomes 1
 * and the conn can emit/receive Handshake-epoch packets.
 *
 * `tx_secret` is the secret used to encrypt OUTBOUND Handshake
 * packets (server: server_handshake_traffic_secret; client:
 * client_handshake_traffic_secret).
 *
 * Returns 0 on success, -1 on key-derivation failure (e.g. unsupported
 * secret length). Idempotent — second call with same arguments is a
 * no-op; calling with different secrets after install is rejected. */
int quic_conn_install_handshake_secrets(quic_conn_t* c,
                                        const uint8_t* tx_secret,
                                        const uint8_t* rx_secret,
                                        size_t secret_len);

/* Set pending Handshake-epoch tx bytes (alias only). */
void quic_conn_handshake_tx_set_pending(quic_conn_t* c,
                                        const uint8_t* bytes, size_t len);

/* Emit one protected Handshake packet. Mirrors quic_conn_emit_initial
 * but uses Handshake-epoch keys + the Handshake long-header type.
 * Returns 0 if no pending bytes, no peer addrs, or no handshake keys. */
size_t quic_conn_emit_handshake(quic_conn_t* c,
                                uint8_t* out, size_t out_cap);

/* Process one received Handshake packet (datagram bytes; UDP already
 * de-multiplexed). Same contract as quic_conn_recv_initial:
 *   - Validates long-header / fixed bit / type=Handshake / version=v1
 *   - Requires handshake_rx keys to be installed
 *   - AEAD-decrypt → walk frames → push CRYPTO bytes into rx_handshake
 *   - Allowed frames per RFC 9000 §17.2.4: PADDING, PING, ACK,
 *     CRYPTO, CONNECTION_CLOSE (transport)
 * Returns 0 on success, -1 on any failure. */
int quic_conn_recv_handshake(quic_conn_t* c,
                             const uint8_t* datagram, size_t len);

const uint8_t* quic_conn_handshake_rx_peek(const quic_conn_t* c,
                                           size_t* out_len);
void quic_conn_handshake_rx_advance(quic_conn_t* c, size_t n);

/* ---- 1-RTT (Application) epoch (wave 5 phase 5e7) ------------------
 *
 * Once the client Finished has been received and verified, the
 * connection transitions to the application data phase. This API
 * pulls the buffered client Finished from the Handshake-epoch
 * reassembler, verifies it against
 * client_handshake_traffic_secret + transcript_hash_thru_server_fin,
 * derives the application-traffic secrets, and installs AES-128-GCM
 * 1-RTT packet keys on the conn.
 *
 * Preconditions: have_handshake_state must be 1 (i.e. the server
 * driver has already run). The Handshake-epoch rx reassembler must
 * have at least one complete Finished message at offset 0.
 *
 * Returns 0 on success, -1 on any failure (no buffered data, malformed
 * Finished message, verify_data mismatch, derivation error). On
 * success, app_keys_ready is set to 1, app_tx_keys / app_rx_keys are
 * populated, and the consumed Finished bytes are advanced out of the
 * Handshake reassembler.
 */
int quic_server_finish_handshake(quic_conn_t* c);

/* ---- 1-RTT (Application) data plane (wave 5/6 phase 6a) ----------- */

uint64_t quic_conn_app_tx_next_pn(const quic_conn_t* c);

/* Build one protected 1-RTT packet carrying `payload` bytes verbatim
 * as the encrypted payload (the caller is responsible for framing —
 * STREAM, MAX_DATA, etc.). Uses app_tx_keys; advances app_tx_next_pn.
 *
 * Returns the wire byte count (>0) or 0 if app_keys_ready==0,
 * peer_addrs_known==0, or out_cap is too small.
 */
size_t quic_conn_emit_app(quic_conn_t* c,
                          const uint8_t* payload, size_t payload_len,
                          uint8_t* out, size_t out_cap);

/* Process one received 1-RTT datagram. Decrypts using app_rx_keys,
 * walks the frames as PADDING/PING/ACK/STREAM-class for now (other
 * frame handling follows in later phases). Returns 0 on success,
 * -1 on any failure. The DCID length is taken from c->our_scid_len —
 * this is the CID the peer was told to address us by. */
int quic_conn_recv_app(quic_conn_t* c,
                       const uint8_t* datagram, size_t len);

#endif