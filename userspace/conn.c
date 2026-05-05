/*
 * Per-connection run-to-completion runtime — see conn.h for the
 * architectural rationale.
 *
 * The pipeline inside `pw_conn_rx`:
 *
 *   1) Push the new bytes into the engine's RX port.
 *
 *   2) `pw_tls_step` opens any complete records into APP_IN. If
 *      no full record is available yet, APP_IN stays empty —
 *      return NEED_MORE.
 *
 *   3) The recovered plaintext (one record's worth) is handed
 *      to `response_fn`. The callee fills a `pw_response_t` of
 *      iov fragments pointing at long-lived storage.
 *
 *   4) `pw_tls_app_seal_iov` seals those fragments straight from
 *      the iov chain into a single outbound record (zero-copy —
 *      no intermediate plaintext buffer between the response_fn's
 *      output and the AEAD).
 *
 *   5) Drain the engine's TX into the caller's `out` buffer.
 *
 * No allocation. All paths are deterministic. Engine handles all
 * AEAD state and buffer bookkeeping; this layer is plumbing.
 */

#include "conn.h"

#include <string.h>

#include "crypto/util.h"
#include "tls/engine.h"

void pw_conn_init(pw_conn_t* c,
                  const tls_record_dir_t* rx_dir,
                  const tls_record_dir_t* tx_dir) {
    memset(c, 0, sizeof(*c));
    pw_tls_engine_init(&c->engine);
    /* Skip the handshake: install pre-derived application-traffic
     * record dirs and jump straight to ST_APP. This shortcut is
     * spike-mode only — production callers should drive the engine
     * through a real handshake via pw_tls_engine_configure_server. */
    pw_tls_engine_install_app_keys(&c->engine,
                                   rx_dir->key, rx_dir->static_iv,
                                   tx_dir->key, tx_dir->static_iv,
                                   1 /*we_are_server*/);
}

pw_conn_status_t pw_conn_rx(pw_conn_t* c,
                            const uint8_t* in, size_t in_len,
                            pw_response_fn response_fn, void* response_user,
                            uint8_t* out, size_t out_cap, size_t* out_len) {
    if (out_len) *out_len = 0;

    /* 1) Push inbound bytes into the engine's RX. The engine's RX
     *    capacity equals PW_CONN_MAX_RECORD so the bound is the same
     *    as the legacy implementation. Oversize is a protocol error. */
    if (in_len) {
        size_t cap = 0;
        uint8_t* rxp = pw_tls_rx_buf(&c->engine, &cap);
        if (in_len > cap) return PW_CONN_PROTOCOL_ERR;
        memcpy(rxp, in, in_len);
        if (pw_tls_rx_ack(&c->engine, in_len) != 0) return PW_CONN_PROTOCOL_ERR;
    }
    c->bytes_in += in_len;

    /* 2) Drive the engine: open any complete record into APP_IN. */
    int w = pw_tls_step(&c->engine);
    if (w < 0) {
        /* Fan out the engine's specific failure class:
         *   AUTH    -> bad AEAD tag / bad client Finished : AUTH_FAIL
         *   anything else (PROTOCOL / OVERFLOW / INTERNAL) : PROTOCOL_ERR
         * Callers can distinguish "they sent us garbage / wrong key"
         * from "they sent us malformed wire bytes". */
        return (pw_tls_last_error(&c->engine) == PW_TLS_ERR_AUTH)
                 ? PW_CONN_AUTH_FAIL
                 : PW_CONN_PROTOCOL_ERR;
    }

    size_t app_in_len = 0;
    const uint8_t* app_in = pw_tls_app_in_buf(&c->engine, &app_in_len);
    if (app_in_len == 0) return PW_CONN_NEED_MORE;
    if (app_in_len > TLS13_MAX_PLAINTEXT) return PW_CONN_PROTOCOL_ERR;

    /* The engine guarantees app_in is one record's worth of plaintext
     * after a single step (try_open_one only opens one at a time and
     * the loop bails when APP_IN is non-empty before a second open).
     * Track records_in by inspecting the engine's counter. */
    c->records_in = c->engine.records_in;

    /* Copy the plaintext request into a stack-stable view BEFORE we
     * ack APP_IN — once ack'd, the engine may reuse those bytes. We
     * use the engine's app_in_buf directly though, snapshotting the
     * pointer/length, then ack at the very end of this function once
     * all consumers have run. (response_fn must not retain the
     * pointer past this call.) */
    const uint8_t* req     = app_in;
    size_t         req_len = app_in_len;

    /* 3) Webserver-as-module: fill response. */
    pw_response_t resp = {0};
    int rrc = response_fn(req, req_len, &resp, response_user);
    if (rrc != 0)                      { pw_tls_app_in_ack(&c->engine, app_in_len); return PW_CONN_RESPONSE_FAIL; }
    if (resp.n > PW_IOV_MAX_FRAGS)     { pw_tls_app_in_ack(&c->engine, app_in_len); return PW_CONN_RESPONSE_FAIL; }

    /* Recompute total_len defensively. */
    size_t total = 0;
    for (unsigned i = 0; i < resp.n; i++) total += resp.parts[i].len;
    if (total > TLS13_MAX_PLAINTEXT)   { pw_tls_app_in_ack(&c->engine, app_in_len); return PW_CONN_RESPONSE_FAIL; }

    /* Done with the inbound plaintext — release it back to the
     * engine so the next request can be parsed. */
    pw_tls_app_in_ack(&c->engine, app_in_len);

    /* 4) Zero-copy seal from the iov chain straight into engine TX. */
    if (out_cap < TLS13_RECORD_HEADER_LEN + total + TLS13_AEAD_TAG_LEN + 1) {
        return PW_CONN_OUT_OVERFLOW;
    }
    if (pw_tls_app_seal_iov(&c->engine, resp.parts, resp.n) != 0) {
        return PW_CONN_OUT_OVERFLOW;
    }

    /* 5) Drain TX into caller's `out` buffer. */
    size_t tx_len = 0;
    const uint8_t* tx = pw_tls_tx_buf(&c->engine, &tx_len);
    if (tx_len == 0)        return PW_CONN_OUT_OVERFLOW;   /* defensive */
    if (tx_len > out_cap)   return PW_CONN_OUT_OVERFLOW;
    memcpy(out, tx, tx_len);
    pw_tls_tx_ack(&c->engine, tx_len);

    if (out_len) *out_len = tx_len;
    c->bytes_out   += tx_len;
    c->records_out  = c->engine.records_out;
    return PW_CONN_OK;
}
