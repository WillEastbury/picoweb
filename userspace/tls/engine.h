/*
 * BearSSL-style explicit TLS state-machine ("engine").
 *
 * The engine is a passive byte-driven state machine. The caller drives
 * I/O on its own terms (epoll, io_uring, DPDK, in-tree dispatch) and
 * calls into the engine to inject ciphertext, drain ciphertext,
 * inject plaintext, drain plaintext. No callbacks. No inversion.
 *
 * Compared to pw_conn (run-to-completion):
 *
 *   pw_conn:    one call walks RX -> TLS open -> HTTP -> TLS seal -> TX
 *               (works, but the caller can't interleave I/O turns)
 *
 *   engine:     four ports the caller drives independently:
 *                  rx_buf/rx_ack       inject ciphertext
 *                  tx_buf/tx_ack       drain ciphertext
 *                  app_in_buf/_ack     drain plaintext
 *                  app_out_push        inject plaintext (sealed on step)
 *               plus a `pw_tls_step` that processes pending work
 *               whenever the caller is ready to drive it.
 *
 * Same architecture, more control. This is the shape the layered
 * pipeline (NIC RX -> TCP -> TLS -> HTTP -> TLS -> TCP -> NIC TX) wants
 * because every layer becomes a bytes-in/bytes-out box.
 *
 * SPIKE NOTE: real handshake completion needs Ed25519 (gating item).
 * To prove the engine state machine works *for application data*,
 * `pw_tls_engine_install_app_keys()` lets a caller (typically a test)
 * inject pre-derived application traffic secrets directly. Once the
 * real handshake lands, the engine walks itself from HANDSHAKE -> APP
 * after exchanging Finished messages, and `install_app_keys` becomes
 * a test-only shortcut.
 */

#ifndef PICOWEB_USERSPACE_TLS_ENGINE_H
#define PICOWEB_USERSPACE_TLS_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "../iov.h"
#include "handshake.h"
#include "record.h"

/* Per-direction buffer cap. Sized for one full TLS record on the
 * wire (header + max ciphertext). Same number for all four ports
 * keeps the engine struct trivially aligned and predictable. */
#define PW_TLS_BUF_CAP  (TLS13_RECORD_HEADER_LEN + TLS13_MAX_CIPHERTEXT)

/* Maximum size of the Certificate handshake message the engine will
 * build (includes the 4-byte handshake header). 8 KiB is more than
 * enough for one or two real certs of typical size; a chain too large
 * to fit is rejected at configure_server time. */
#define PW_TLS_ENGINE_CERT_MSG_MAX 8192u

typedef enum {
    PW_TLS_ST_HANDSHAKE = 0,   /* no app keys yet, can't process records   */
    PW_TLS_ST_APP       = 1,   /* keys installed, processing app data      */
    PW_TLS_ST_CLOSED    = 2,   /* close_notify exchanged (or scheduled)    */
    PW_TLS_ST_FAILED    = 3,   /* fatal protocol error - engine inert      */
} pw_tls_state_t;

/* Reason the engine entered PW_TLS_ST_FAILED. Set by the engine
 * before transitioning to FAILED; readable via pw_tls_last_error.
 *
 *   NONE      no fatal error has occurred (engine is healthy or
 *             deliberately CLOSED rather than FAILED)
 *   AUTH      cryptographic authentication failed: AEAD tag
 *             rejected or peer Finished verify_data mismatch.
 *             This is the only class that strongly suggests a
 *             tampered or wrong-keyed peer.
 *   PROTOCOL  malformed wire format, unexpected content type,
 *             oversize record, unsupported version/cipher, etc.
 *             Default for any fatal that isn't explicitly tagged.
 *   OVERFLOW  caller exceeded a buffer cap (pushed plaintext too
 *             large to seal in one record, etc.)
 *   INTERNAL  an internal subsystem failed (RNG, build helper).
 *             Almost certainly a bug in the engine or its host.
 */
typedef enum {
    PW_TLS_ERR_NONE     = 0,
    PW_TLS_ERR_AUTH     = 1,
    PW_TLS_ERR_PROTOCOL = 2,
    PW_TLS_ERR_OVERFLOW = 3,
    PW_TLS_ERR_INTERNAL = 4,
} pw_tls_err_t;

/* Sub-state inside HANDSHAKE — tracks where we are in the handshake
 * flight. Only meaningful while state == PW_TLS_ST_HANDSHAKE. */
typedef enum {
    PW_TLS_HS_WAIT_CH         = 0,  /* server: waiting for ClientHello       */
    PW_TLS_HS_AFTER_SH_KEYS   = 1,  /* server: SH sent, hs traffic keys in   */
    PW_TLS_HS_AFTER_SF_AWAIT_CF = 2,/* server: EE/Cert/CV/sFin sent, app
                                       secrets cached; awaiting client Fin  */
} pw_tls_hs_phase_t;

/* Bitmask returned by pw_tls_want(). The caller checks these to know
 * which I/O turns are productive. */
#define PW_TLS_WANT_RX     (1u << 0)   /* engine has room for more cipher  */
#define PW_TLS_WANT_TX     (1u << 1)   /* engine has cipher to send out    */
#define PW_TLS_APP_IN_RDY  (1u << 2)   /* plaintext available to drain     */
#define PW_TLS_APP_OUT_OK  (1u << 3)   /* engine can accept plaintext      */

/* RNG callback. Fills exactly `n` bytes into `dst` and returns 0; any
 * non-zero return is treated as a fatal RNG failure (engine -> FAILED).
 * `user` is the opaque cookie passed to pw_tls_engine_configure_server. */
typedef int (*pw_tls_rng_fn)(void* user, uint8_t* dst, size_t n);

typedef struct pw_tls_engine {
    pw_tls_state_t    state;
    pw_tls_hs_phase_t hs_phase;
    pw_tls_err_t      last_err;     /* set on transition to FAILED        */

    /* Inbound ciphertext (post-TCP, pre-AEAD). */
    uint8_t  rx_buf[PW_TLS_BUF_CAP];
    size_t   rx_len;

    /* Outbound ciphertext (post-AEAD, pre-TCP). */
    uint8_t  tx_buf[PW_TLS_BUF_CAP];
    size_t   tx_len;

    /* Inbound plaintext (post-AEAD-open, the application will read). */
    uint8_t  app_in_buf[PW_TLS_BUF_CAP];
    size_t   app_in_len;

    /* Outbound plaintext (the application has written, waits for seal). */
    uint8_t  app_out_buf[PW_TLS_BUF_CAP];
    size_t   app_out_len;

    /* Per-direction record state. Read = decrypt our peer's records;
     * write = encrypt records we send. */
    tls_record_dir_t read;
    tls_record_dir_t write;

    int      keys_installed;
    int      we_are_server;

    /* ------------------------------------------------------------------
     * Server-side handshake config (set by pw_tls_engine_configure_server).
     * The engine borrows cert_chain_der / cert_lens — caller MUST keep
     * them alive for the engine's lifetime. seed_ed25519 is COPIED.
     * ------------------------------------------------------------------ */
    int               configured;
    pw_tls_rng_fn     rng_fn;
    void*             rng_user;
    uint8_t           seed_ed25519[32];
    const uint8_t*    cert_chain_der;
    const size_t*     cert_lens;
    unsigned          n_certs;

    /* ------------------------------------------------------------------
     * Live handshake context (populated as the handshake progresses).
     * ------------------------------------------------------------------ */
    tls13_transcript_t transcript;
    uint8_t           server_random[32];
    uint8_t           eph_priv[32];
    uint8_t           eph_pub[32];
    uint8_t           handshake_secret[32];
    uint8_t           cs_handshake_secret[32];   /* client -> server */
    uint8_t           ss_handshake_secret[32];   /* server -> client */

    /* Application-phase secrets (cached after sFin emission, used to
     * derive the read+write app keys after the client Finished is
     * verified). */
    uint8_t           master_secret[32];
    uint8_t           cs_app_traffic_secret[32];
    uint8_t           ss_app_traffic_secret[32];

    /* RFC 8446 §7.1 resumption_master_secret. Derived from master_secret
     * and transcript through the client Finished. Used as the IKM for
     * future PSKs (NewSessionTicket / resumption). Computed in the
     * handshake-completion path; persists into APP state. */
    uint8_t           resumption_master_secret[32];
    int               has_rms;

    /* ------------------------------------------------------------------
     * Resumption / 0-RTT context. The engine BORROWS the ticket store —
     * caller keeps it alive across the engine's lifetime. now_ms is the
     * caller's monotonic clock in milliseconds, used for ticket
     * expiry. Set both via pw_tls_engine_attach_resumption + before
     * each step where time-sensitive decisions matter
     * (pw_tls_engine_set_clock).
     *
     * `resumed` is set to 1 once a PSK was successfully accepted on
     * a resumption handshake; the server flight then SKIPs Certificate
     * + CertificateVerify per RFC 8446 §4.6.1.
     *
     * `selected_psk_identity` is the index of the accepted offer in
     * the client's pre_shared_key extension (0-based).
     *
     * `selected_psk[32]` is the per-ticket PSK installed for this
     * handshake; wiped at handshake completion. ------------------ */
    struct pw_tls_ticket_store* ticket_store;   /* borrowed */
    uint64_t          now_ms;
    int               resumed;
    int               selected_psk_identity;
    uint8_t           selected_psk[32];

    /* 0-RTT acceptance flags. `early_data_accepted` indicates the
     * server has accepted early data (will surface plaintext via
     * APP_IN before cFin). `early_data_max` is the per-ticket cap
     * (0 if not accepting). `early_data_seen` counts plaintext bytes
     * already surfaced; used to enforce the cap. */
    int               early_data_accepted;
    uint32_t          early_data_max;
    uint32_t          early_data_seen;

    /* 0-RTT runtime state.
     * early_data_phase: 0 = none, 1 = ACTIVE (eng->read.key holds the
     *   client_early_traffic-derived key, expecting application_data
     *   inner=APP_DATA OR EndOfEarlyData),
     * 2 = DONE (EOED seen, eng->read.key now holds the
     *   handshake-traffic key from saved_hs_read_*).
     *
     * saved_hs_read_*[]: derived (key,iv) for the cs_handshake_traffic
     * secret, stashed at install time so we can swap to it after EOED
     * without re-deriving from secret material that might have been
     * wiped. */
    int               early_data_phase;
    uint8_t           saved_hs_read_key[32];
    uint8_t           saved_hs_read_iv[12];

    /* Diagnostics. */
    uint64_t records_in;
    uint64_t records_out;
} pw_tls_engine_t;

/* ---------- lifecycle ---------- */

void pw_tls_engine_init(pw_tls_engine_t* eng);

/* Configure the engine as a TLS 1.3 server. Once configured, pw_tls_step
 * will drive a real handshake when ClientHello bytes arrive in RX.
 *
 * Inputs:
 *   rng_fn / rng_user     — entropy source (returns 0 on success)
 *   seed_ed25519[32]      — raw Ed25519 seed (use cert_extract_ed25519_seed)
 *                           COPIED into the engine.
 *   cert_chain_der        — concatenated DER X.509 chain (server cert
 *                           first). BORROWED — caller MUST keep alive
 *                           for the engine's lifetime.
 *   cert_lens[n_certs]    — per-cert byte lengths in chain order.
 *                           BORROWED.
 *   n_certs               — number of certs in chain (>= 1).
 *
 * Returns 0 on success, -1 on bad args. */
int pw_tls_engine_configure_server(pw_tls_engine_t* eng,
                                   pw_tls_rng_fn rng_fn,
                                   void* rng_user,
                                   const uint8_t seed_ed25519[32],
                                   const uint8_t* cert_chain_der,
                                   const size_t* cert_lens,
                                   unsigned n_certs);

/* Spike-mode shortcut: install pre-derived app traffic keys directly,
 * BYPASSING the handshake. Lets a test exercise the APP-state engine
 * paths without doing a real handshake. Once the full handshake driver
 * is in place this becomes test-only.
 *
 * Ordering of (key, iv) follows TLS 1.3: client->server keys decrypt
 * what the client sends; server->client keys encrypt what we send to
 * the client (when we_are_server=1). Returns 0. */
int pw_tls_engine_install_app_keys(pw_tls_engine_t* eng,
                                   const uint8_t client_app_key[32],
                                   const uint8_t client_app_iv[12],
                                   const uint8_t server_app_key[32],
                                   const uint8_t server_app_iv[12],
                                   int we_are_server);

/* Schedule close: state -> CLOSED. (close_notify alert emission TBD;
 * BearSSL emits a real alert here. For the spike, we just drop into
 * CLOSED so the caller stops polling.) */
void pw_tls_close(pw_tls_engine_t* eng);

/* Attach a ticket store for both NewSessionTicket emission and
 * inbound PSK acceptance. The engine BORROWS the pointer; caller
 * keeps the store alive. May be called once after configure_server
 * but before the first pw_tls_step. Pass NULL to detach. */
struct pw_tls_ticket_store;
void pw_tls_engine_attach_resumption(pw_tls_engine_t* eng,
                                     struct pw_tls_ticket_store* store);

/* Update the engine's monotonic millisecond clock. Used for ticket
 * expiry checks during PSK acceptance. Caller should call this just
 * before pw_tls_step on each driver loop iteration that may consume
 * a ClientHello. */
void pw_tls_engine_set_clock(pw_tls_engine_t* eng, uint64_t now_ms);

/* Returns 1 iff the engine successfully completed a resumption
 * handshake (PSK accepted). 0 otherwise. */
int  pw_tls_engine_was_resumed(const pw_tls_engine_t* eng);

/* Returns 1 iff 0-RTT early data was accepted on this handshake. */
int  pw_tls_engine_early_data_accepted(const pw_tls_engine_t* eng);

/* Emit a single NewSessionTicket (RFC 8446 §4.6.1) record on the TX
 * port, sealed under the current server-application-traffic write key.
 *
 * Pre-conditions:
 *   - pw_tls_state(eng) == PW_TLS_ST_APP
 *   - eng->has_rms == 1 (resumption_master_secret available)
 *
 * Caller supplies `ticket_nonce` (1..255 bytes) and `ticket_id`
 * (1..65535 bytes; the opaque label the client will return on
 * resumption). Server stores (ticket_id, derived_psk, age_add,
 * lifetime_s, issued_at_ms) externally; this function does NOT
 * touch any store.
 *
 * Per-ticket PSK is derived as
 *   PSK = HKDF-Expand-Label(RMS, "resumption", ticket_nonce, 32)
 * and written into `out_psk` for the caller to insert into its store.
 *
 * Returns 0 on success, -1 on bad args / TX overflow / wrong state. */
int pw_tls_engine_emit_session_ticket(pw_tls_engine_t* eng,
                                      uint32_t lifetime_s,
                                      uint32_t age_add,
                                      const uint8_t* ticket_nonce,
                                      size_t nonce_len,
                                      const uint8_t* ticket_id,
                                      size_t id_len,
                                      uint8_t out_psk[32]);

/* ---------- state introspection ---------- */

pw_tls_state_t    pw_tls_state(const pw_tls_engine_t* eng);
pw_tls_hs_phase_t pw_tls_hs_phase(const pw_tls_engine_t* eng);
unsigned          pw_tls_want(const pw_tls_engine_t* eng);

/* Reason for the most recent transition to PW_TLS_ST_FAILED. Returns
 * PW_TLS_ERR_NONE if the engine has not failed (including when it is
 * deliberately CLOSED). Stable until the engine is re-init'd. */
pw_tls_err_t      pw_tls_last_error(const pw_tls_engine_t* eng);

/* ---------- RX port (caller writes ciphertext into engine) ---------- */

/* Returns a writable pointer into the engine's RX buffer and the
 * available capacity. Caller writes `n <= cap` bytes then commits via
 * pw_tls_rx_ack. */
uint8_t* pw_tls_rx_buf(pw_tls_engine_t* eng, size_t* cap);
int      pw_tls_rx_ack(pw_tls_engine_t* eng, size_t n);

/* ---------- TX port (caller reads ciphertext from engine) ---------- */

const uint8_t* pw_tls_tx_buf(pw_tls_engine_t* eng, size_t* len);
int            pw_tls_tx_ack(pw_tls_engine_t* eng, size_t n);

/* ---------- APP IN port (caller reads plaintext from engine) ---------- */

const uint8_t* pw_tls_app_in_buf(pw_tls_engine_t* eng, size_t* len);
int            pw_tls_app_in_ack(pw_tls_engine_t* eng, size_t n);

/* ---------- APP OUT port (caller writes plaintext into engine) ---------- */

/* Append the concatenation of iov[0..n) to the app-out buffer. Will
 * be sealed into a TLS record on the next pw_tls_step. Returns 0 on
 * success, -1 if the engine has no room (app_out_buf full).
 *
 * The total length must fit in PW_TLS_BUF_CAP minus a small overhead;
 * larger payloads should be pushed across multiple steps (caller
 * drains TX between pushes). */
int pw_tls_app_out_push(pw_tls_engine_t* eng,
                        const pw_iov_t* iov, unsigned n);

/* Zero-copy variant: seal the iov chain directly into a single TLS
 * application_data record and append the record bytes to TX. This
 * BYPASSES the app_out buffer copy, preserving the iov property end
 * to end. Used by `pw_conn` (and any future hot-path service) that
 * already has its response fragments laid out in immutable storage.
 *
 * Constraints:
 *   - engine state must be PW_TLS_ST_APP (handshake is complete)
 *   - sum(iov[i].len) <= TLS13_MAX_PLAINTEXT
 *   - TX must have room for header + plaintext + 1 (type) + AEAD tag
 *
 * Returns 0 on success, -1 on bad state / overflow / seal failure. */
int pw_tls_app_seal_iov(pw_tls_engine_t* eng,
                        const pw_iov_t* iov, unsigned n);

/* ---------- step ---------- */

/* Drive the engine forward: open any pending records in RX (write to
 * APP_IN if room), seal any pending APP_OUT bytes into TX (one record
 * per call). Idempotent and re-entrancy-safe. Returns the new want
 * bitmask, or -1 if a fatal protocol error occurred (state -> FAILED). */
int pw_tls_step(pw_tls_engine_t* eng);

#endif
