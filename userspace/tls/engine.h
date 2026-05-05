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
#include "record.h"

/* Per-direction buffer cap. Sized for one full TLS record on the
 * wire (header + max ciphertext). Same number for all four ports
 * keeps the engine struct trivially aligned and predictable. */
#define PW_TLS_BUF_CAP  (TLS13_RECORD_HEADER_LEN + TLS13_MAX_CIPHERTEXT)

typedef enum {
    PW_TLS_ST_HANDSHAKE = 0,   /* no app keys yet, can't process records   */
    PW_TLS_ST_APP       = 1,   /* keys installed, processing app data      */
    PW_TLS_ST_CLOSED    = 2,   /* close_notify exchanged (or scheduled)    */
    PW_TLS_ST_FAILED    = 3,   /* fatal protocol error - engine inert      */
} pw_tls_state_t;

/* Bitmask returned by pw_tls_want(). The caller checks these to know
 * which I/O turns are productive. */
#define PW_TLS_WANT_RX     (1u << 0)   /* engine has room for more cipher  */
#define PW_TLS_WANT_TX     (1u << 1)   /* engine has cipher to send out    */
#define PW_TLS_APP_IN_RDY  (1u << 2)   /* plaintext available to drain     */
#define PW_TLS_APP_OUT_OK  (1u << 3)   /* engine can accept plaintext      */

typedef struct pw_tls_engine {
    pw_tls_state_t state;

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

    /* Diagnostics. */
    uint64_t records_in;
    uint64_t records_out;
} pw_tls_engine_t;

/* ---------- lifecycle ---------- */

void pw_tls_engine_init(pw_tls_engine_t* eng);

/* Spike-mode shortcut: install pre-derived app traffic keys directly.
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

/* ---------- state introspection ---------- */

pw_tls_state_t pw_tls_state(const pw_tls_engine_t* eng);
unsigned       pw_tls_want(const pw_tls_engine_t* eng);

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

/* ---------- step ---------- */

/* Drive the engine forward: open any pending records in RX (write to
 * APP_IN if room), seal any pending APP_OUT bytes into TX (one record
 * per call). Idempotent and re-entrancy-safe. Returns the new want
 * bitmask, or -1 if a fatal protocol error occurred (state -> FAILED). */
int pw_tls_step(pw_tls_engine_t* eng);

#endif
