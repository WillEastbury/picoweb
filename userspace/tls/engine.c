/*
 * BearSSL-style TLS engine (TLS 1.3, ChaCha20-Poly1305 only).
 *
 * Passive byte-driven state machine. See engine.h for the full API
 * contract. This impl processes records one at a time per `pw_tls_step`
 * call, which keeps memory predictable and lets the caller bound how
 * much CPU the engine can consume per turn.
 */

#include "engine.h"

#include <string.h>

#include "../crypto/util.h"
#include "../crypto/sha256.h"
#include "../crypto/x25519.h"
#include "handshake.h"
#include "keysched.h"
#include "record.h"
#include "ticket_store.h"

/* Memory-shift the head of a buffer down by `n` bytes. Used after
 * draining ciphertext from RX or after the caller acks plaintext
 * from APP_IN. Linear shift is fine here - max move is one record
 * (~16KB) and shifts only happen when drains lag input. */
static void buf_shift(uint8_t* buf, size_t* len, size_t n) {
    if (n == 0 || n > *len) return;
    size_t rem = *len - n;
    if (rem) memmove(buf, buf + n, rem);
    *len = rem;
}

/* ----------------------- lifecycle ----------------------- */

void pw_tls_engine_init(pw_tls_engine_t* eng) {
    if (!eng) return;
    /* Zero the whole struct including buffers. The buffers are large
     * (4 * PW_TLS_BUF_CAP ~= 66KB) and a fresh engine MUST not leak
     * any prior caller's data. */
    secure_zero(eng, sizeof(*eng));
    eng->state    = PW_TLS_ST_HANDSHAKE;
    eng->hs_phase = PW_TLS_HS_WAIT_CH;
}

int pw_tls_engine_configure_server(pw_tls_engine_t* eng,
                                   pw_tls_rng_fn rng_fn,
                                   void* rng_user,
                                   const uint8_t seed_ed25519[32],
                                   const uint8_t* cert_chain_der,
                                   const size_t* cert_lens,
                                   unsigned n_certs) {
    if (!eng || !rng_fn || !seed_ed25519) return -1;
    if (n_certs == 0 || !cert_chain_der || !cert_lens) return -1;
    if (eng->state != PW_TLS_ST_HANDSHAKE) return -1;
    if (eng->hs_phase != PW_TLS_HS_WAIT_CH) return -1;

    /* Validate cert chain fits in the per-message stack scratch the
     * flight emitter uses (PW_TLS_ENGINE_CERT_MSG_MAX). Catching
     * misconfiguration at config time is much friendlier than mid-
     * handshake — the latter would expose us to peers seeing a
     * partial handshake before we abort. */
    size_t cert_msg_size = 4 + 1 + 3;       /* hdr + ctx_len + list_len */
    for (unsigned i = 0; i < n_certs; i++) {
        if (cert_lens[i] == 0 || cert_lens[i] > 0xFFFFFFu) return -1;
        cert_msg_size += 3 + cert_lens[i] + 2;
    }
    if (cert_msg_size > PW_TLS_ENGINE_CERT_MSG_MAX) return -1;

    eng->rng_fn         = rng_fn;
    eng->rng_user       = rng_user;
    memcpy(eng->seed_ed25519, seed_ed25519, 32);
    eng->cert_chain_der = cert_chain_der;
    eng->cert_lens      = cert_lens;
    eng->n_certs        = n_certs;
    eng->we_are_server  = 1;
    eng->configured     = 1;
    return 0;
}

int pw_tls_engine_install_app_keys(pw_tls_engine_t* eng,
                                   const uint8_t client_app_key[32],
                                   const uint8_t client_app_iv[12],
                                   const uint8_t server_app_key[32],
                                   const uint8_t server_app_iv[12],
                                   int we_are_server) {
    if (!eng) return -1;
    if (eng->state == PW_TLS_ST_FAILED || eng->state == PW_TLS_ST_CLOSED) return -1;

    /* As a server we DECRYPT with client keys (read) and ENCRYPT with
     * server keys (write). As a client the polarity flips. */
    if (we_are_server) {
        memcpy(eng->read.key,        client_app_key, 32);
        memcpy(eng->read.static_iv,  client_app_iv,  12);
        memcpy(eng->write.key,       server_app_key, 32);
        memcpy(eng->write.static_iv, server_app_iv,  12);
    } else {
        memcpy(eng->read.key,        server_app_key, 32);
        memcpy(eng->read.static_iv,  server_app_iv,  12);
        memcpy(eng->write.key,       client_app_key, 32);
        memcpy(eng->write.static_iv, client_app_iv,  12);
    }
    eng->read.seq       = 0;
    eng->write.seq      = 0;
    eng->we_are_server  = we_are_server ? 1 : 0;
    eng->keys_installed = 1;
    eng->state          = PW_TLS_ST_APP;
    return 0;
}

void pw_tls_close(pw_tls_engine_t* eng) {
    if (!eng) return;
    /* TODO: emit close_notify alert into TX (TLS 1.3 §6.1). For the
     * spike we just transition state so the caller stops polling. */
    eng->state = PW_TLS_ST_CLOSED;
}

void pw_tls_engine_attach_resumption(pw_tls_engine_t* eng,
                                     struct pw_tls_ticket_store* store) {
    if (!eng) return;
    eng->ticket_store = store;
}

void pw_tls_engine_set_clock(pw_tls_engine_t* eng, uint64_t now_ms) {
    if (!eng) return;
    eng->now_ms = now_ms;
}

int pw_tls_engine_was_resumed(const pw_tls_engine_t* eng) {
    return (eng && eng->resumed) ? 1 : 0;
}

int pw_tls_engine_early_data_accepted(const pw_tls_engine_t* eng) {
    return (eng && eng->early_data_accepted) ? 1 : 0;
}

int pw_tls_engine_emit_session_ticket(pw_tls_engine_t* eng,
                                      uint32_t lifetime_s,
                                      uint32_t age_add,
                                      const uint8_t* ticket_nonce,
                                      size_t nonce_len,
                                      const uint8_t* ticket_id,
                                      size_t id_len,
                                      uint8_t out_psk[32]) {
    if (!eng || !ticket_nonce || !ticket_id || !out_psk)         return -1;
    if (eng->state != PW_TLS_ST_APP || eng->has_rms != 1)        return -1;
    if (nonce_len == 0 || nonce_len > 255)                       return -1;
    if (id_len    == 0 || id_len    > 0xffff)                    return -1;

    /* Derive per-ticket PSK for the caller's ticket store. */
    if (tls13_derive_resumption_psk(eng->resumption_master_secret,
                                    ticket_nonce, nonce_len,
                                    out_psk) != 0) return -1;

    /* Build NST plaintext. Worst-case ~ 4 + 13 + 255 + 65535 — too
     * large to stack-alloc safely. We bound to TLS13_MAX_PLAINTEXT
     * (16384) which more than covers any reasonable ticket id. */
    uint8_t nst[TLS13_MAX_PLAINTEXT];
    int nst_len = tls13_build_new_session_ticket(nst, sizeof(nst),
                                                 lifetime_s, age_add,
                                                 ticket_nonce, nonce_len,
                                                 ticket_id, id_len);
    if (nst_len <= 0) { secure_zero(out_psk, 32); return -1; }

    size_t need = TLS13_RECORD_HEADER_LEN + (size_t)nst_len + 1 + TLS13_AEAD_TAG_LEN;
    if (need > PW_TLS_BUF_CAP - eng->tx_len) {
        secure_zero(out_psk, 32);
        secure_zero(nst,     sizeof(nst));
        return -1;
    }

    size_t wrote = tls13_seal_record(&eng->write,
                                     TLS_CT_HANDSHAKE,
                                     TLS_CT_APPLICATION_DATA,
                                     nst, (size_t)nst_len,
                                     eng->tx_buf + eng->tx_len,
                                     PW_TLS_BUF_CAP - eng->tx_len);
    secure_zero(nst, sizeof(nst));
    if (wrote == 0) { secure_zero(out_psk, 32); return -1; }
    eng->tx_len += wrote;
    eng->records_out++;
    return 0;
}

/* ----------------------- introspection ----------------------- */

pw_tls_state_t pw_tls_state(const pw_tls_engine_t* eng) {
    return eng ? eng->state : PW_TLS_ST_FAILED;
}

pw_tls_hs_phase_t pw_tls_hs_phase(const pw_tls_engine_t* eng) {
    return eng ? eng->hs_phase : PW_TLS_HS_WAIT_CH;
}

pw_tls_err_t pw_tls_last_error(const pw_tls_engine_t* eng) {
    return eng ? eng->last_err : PW_TLS_ERR_INTERNAL;
}

unsigned pw_tls_want(const pw_tls_engine_t* eng) {
    if (!eng) return 0;
    if (eng->state == PW_TLS_ST_CLOSED || eng->state == PW_TLS_ST_FAILED) {
        /* Even when closed, drain any leftover TX so caller can flush. */
        return eng->tx_len ? PW_TLS_WANT_TX : 0;
    }
    unsigned w = 0;
    /* RX/TX bytes are the transport's concern - same semantics in
     * HANDSHAKE and APP. */
    if (eng->rx_len < PW_TLS_BUF_CAP)     w |= PW_TLS_WANT_RX;
    if (eng->tx_len > 0)                   w |= PW_TLS_WANT_TX;
    /* APP-level ports are only valid once we're past the handshake. */
    if (eng->state == PW_TLS_ST_APP) {
        if (eng->app_in_len > 0)               w |= PW_TLS_APP_IN_RDY;
        if (eng->app_out_len < PW_TLS_BUF_CAP) w |= PW_TLS_APP_OUT_OK;
    }
    return w;
}

/* ----------------------- RX port ----------------------- */

/* Forward decl: mark a pending fatal error class. Definition appears
 * with the rest of the failure helpers below. */
static inline void engine_mark_err(pw_tls_engine_t* eng, pw_tls_err_t e);

uint8_t* pw_tls_rx_buf(pw_tls_engine_t* eng, size_t* cap) {
    if (!eng) { if (cap) *cap = 0; return NULL; }
    if (cap) *cap = PW_TLS_BUF_CAP - eng->rx_len;
    return eng->rx_buf + eng->rx_len;
}

int pw_tls_rx_ack(pw_tls_engine_t* eng, size_t n) {
    if (!eng) return -1;
    if (n > PW_TLS_BUF_CAP - eng->rx_len) return -1;
    eng->rx_len += n;
    return 0;
}

/* ----------------------- TX port ----------------------- */

const uint8_t* pw_tls_tx_buf(pw_tls_engine_t* eng, size_t* len) {
    if (!eng) { if (len) *len = 0; return NULL; }
    if (len) *len = eng->tx_len;
    return eng->tx_buf;
}

int pw_tls_tx_ack(pw_tls_engine_t* eng, size_t n) {
    if (!eng || n > eng->tx_len) return -1;
    buf_shift(eng->tx_buf, &eng->tx_len, n);
    return 0;
}

/* ----------------------- APP IN port ----------------------- */

const uint8_t* pw_tls_app_in_buf(pw_tls_engine_t* eng, size_t* len) {
    if (!eng) { if (len) *len = 0; return NULL; }
    if (len) *len = eng->app_in_len;
    return eng->app_in_buf;
}

int pw_tls_app_in_ack(pw_tls_engine_t* eng, size_t n) {
    if (!eng || n > eng->app_in_len) return -1;
    /* Zero the consumed plaintext bytes before sliding so the engine
     * doesn't retain old request bodies in memory after the caller
     * has drained them. (Rubber-duck blocker on pw_conn migration.)
     * After buf_shift the surviving bytes live in [0, app_in_len-n);
     * the bytes we just consumed are at the original [0, n) position.
     * Easiest correct approach: shift first, then zero the vacated
     * tail [new_len, old_len). */
    size_t old_len = eng->app_in_len;
    buf_shift(eng->app_in_buf, &eng->app_in_len, n);
    secure_zero(eng->app_in_buf + eng->app_in_len, old_len - eng->app_in_len);
    return 0;
}

/* ----------------------- APP OUT port ----------------------- */

int pw_tls_app_out_push(pw_tls_engine_t* eng,
                        const pw_iov_t* iov, unsigned n) {
    if (!eng) return -1;
    if (eng->state != PW_TLS_ST_APP) return -1;

    size_t total = 0;
    for (unsigned i = 0; i < n; i++) total += iov[i].len;
    if (total > PW_TLS_BUF_CAP - eng->app_out_len) return -1;

    size_t off = eng->app_out_len;
    for (unsigned i = 0; i < n; i++) {
        memcpy(eng->app_out_buf + off, iov[i].base, iov[i].len);
        off += iov[i].len;
    }
    eng->app_out_len = off;
    return 0;
}

int pw_tls_app_seal_iov(pw_tls_engine_t* eng,
                        const pw_iov_t* iov, unsigned n) {
    if (!eng) return -1;
    if (eng->state != PW_TLS_ST_APP) return -1;

    size_t total = 0;
    for (unsigned i = 0; i < n; i++) total += iov[i].len;
    if (total > TLS13_MAX_PLAINTEXT) return -1;

    size_t need = TLS13_RECORD_HEADER_LEN + total + 1 + TLS13_AEAD_TAG_LEN;
    if (need > PW_TLS_BUF_CAP - eng->tx_len) return -1;

    size_t wrote = tls13_seal_record_iov(&eng->write,
                                         TLS_CT_APPLICATION_DATA,
                                         TLS_CT_APPLICATION_DATA,
                                         iov, n, total,
                                         eng->tx_buf + eng->tx_len,
                                         PW_TLS_BUF_CAP - eng->tx_len);
    if (wrote == 0) return -1;
    eng->tx_len += wrote;
    eng->records_out++;
    return 0;
}

/* ----------------------- step ----------------------- */

/* Try to open one TLS record from the head of RX into APP_IN.
 * Returns 1 if a record was processed, 0 if not enough RX bytes,
 * -1 on protocol/auth error. */
static int try_open_one(pw_tls_engine_t* eng) {
    if (eng->rx_len < TLS13_RECORD_HEADER_LEN) return 0;

    /* Header: type(1) version(2) length(2). */
    uint16_t rec_len = ((uint16_t)eng->rx_buf[3] << 8) | eng->rx_buf[4];
    size_t   total   = TLS13_RECORD_HEADER_LEN + rec_len;
    if (total > PW_TLS_BUF_CAP)             return -1;
    if (eng->rx_len < total)                return 0;

    /* Open in place, then copy plaintext into APP_IN. We can't open
     * directly into APP_IN because the open is in-place over the
     * record bytes (header + ciphertext) and APP_IN must hold only
     * recovered plaintext. */
    tls_content_type_t inner = TLS_CT_INVALID;
    uint8_t* pt = NULL;
    size_t   pt_len = 0;
    int rc = tls13_open_record(&eng->read,
                               eng->rx_buf, total,
                               &inner, &pt, &pt_len);
    if (rc < 0) {
        /* AEAD authentication failed (bad tag / wrong key / tampered
         * ciphertext). This is the canonical AUTH-class failure. */
        engine_mark_err(eng, PW_TLS_ERR_AUTH);
        return -1;
    }

    /* tls13_open_record already advances eng->read.seq on success
     * (record.c line 109). We MUST NOT bump again here — doing so
     * would skip seq=1 entirely and the second record would use the
     * wrong nonce, breaking interop with any RFC-conformant peer.
     * (Earlier code bumped twice; tests didn't catch it because both
     * server and client engines bumped symmetrically.) */
    eng->records_in++;

    if (inner == TLS_CT_APPLICATION_DATA) {
        if (pt_len > PW_TLS_BUF_CAP - eng->app_in_len) {
            /* APP_IN full - leave the record in RX, the caller must
             * drain APP_IN and call step again. We already bumped seq
             * and consumed the record though, so we can't actually
             * leave it - this is a logic bug in the spike. For now,
             * if APP_IN is full we drop and signal protocol error. */
            engine_mark_err(eng, PW_TLS_ERR_OVERFLOW);
            return -1;
        }
        memcpy(eng->app_in_buf + eng->app_in_len, pt, pt_len);
        eng->app_in_len += pt_len;
    } else if (inner == TLS_CT_ALERT) {
        /* RFC 8446 §6: any alert closes the connection.
         * Differentiating warning vs fatal is a refinement we'll add
         * when the handshake completes end-to-end. */
        eng->state = PW_TLS_ST_CLOSED;
    } else if (inner == TLS_CT_HANDSHAKE) {
        /* Post-handshake handshake messages (NewSessionTicket,
         * KeyUpdate) - silently consumed for the spike. */
    } else {
        /* Unknown content type after handshake - protocol error. */
        return -1;
    }

    /* Slide RX buffer forward past this record. */
    buf_shift(eng->rx_buf, &eng->rx_len, total);
    return 1;
}

/* Try to seal one TLS record from APP_OUT into TX. Returns 1 if a
 * record was emitted, 0 if APP_OUT empty or TX full, -1 on overflow. */
static int try_seal_one(pw_tls_engine_t* eng) {
    if (eng->app_out_len == 0) return 0;
    /* Cap a single record at TLS13_MAX_PLAINTEXT - any leftover stays
     * in APP_OUT for the next step. */
    size_t pt_len = eng->app_out_len;
    if (pt_len > TLS13_MAX_PLAINTEXT) pt_len = TLS13_MAX_PLAINTEXT;

    size_t need = TLS13_RECORD_HEADER_LEN + pt_len + 1 + TLS13_AEAD_TAG_LEN;
    if (need > PW_TLS_BUF_CAP - eng->tx_len) return 0;

    size_t wrote = tls13_seal_record(&eng->write,
                                     TLS_CT_APPLICATION_DATA,
                                     TLS_CT_APPLICATION_DATA,
                                     eng->app_out_buf, pt_len,
                                     eng->tx_buf + eng->tx_len,
                                     PW_TLS_BUF_CAP - eng->tx_len);
    if (wrote == 0) return -1;

    /* tls13_seal_record already advances eng->write.seq on success
     * (record.c line 59). Do NOT bump here — same reasoning as the
     * read side above. */
    eng->tx_len += wrote;
    eng->records_out++;

    /* Advance APP_OUT past the bytes we just sealed. */
    buf_shift(eng->app_out_buf, &eng->app_out_len, pt_len);
    return 1;
}

/* ----------------------- handshake driver (server) ----------------------- */

/* Wipe handshake-context secrets AND any installed record-layer keys
 * after a fatal handshake error or after a successful transition to
 * APP. Caller is responsible for advancing state. */
static void wipe_handshake_secrets(pw_tls_engine_t* eng) {
    secure_zero(eng->eph_priv,             sizeof(eng->eph_priv));
    secure_zero(eng->handshake_secret,     sizeof(eng->handshake_secret));
    secure_zero(eng->cs_handshake_secret,  sizeof(eng->cs_handshake_secret));
    secure_zero(eng->ss_handshake_secret,  sizeof(eng->ss_handshake_secret));
    secure_zero(eng->master_secret,        sizeof(eng->master_secret));
    secure_zero(eng->cs_app_traffic_secret, sizeof(eng->cs_app_traffic_secret));
    secure_zero(eng->ss_app_traffic_secret, sizeof(eng->ss_app_traffic_secret));
    secure_zero(eng->resumption_master_secret, sizeof(eng->resumption_master_secret));
    eng->has_rms = 0;
    /* Resumption + 0-RTT context. The accepted-PSK material lives only
     * for the handshake; once we transition to APP we no longer need it. */
    secure_zero(eng->selected_psk,        sizeof(eng->selected_psk));
    secure_zero(eng->saved_hs_read_key,   sizeof(eng->saved_hs_read_key));
    secure_zero(eng->saved_hs_read_iv,    sizeof(eng->saved_hs_read_iv));
}

/* Wipe ALL key material — secrets + installed record-layer keys/IVs
 * + their sequence numbers. Used on fatal handshake failure so an
 * engine in FAILED state retains no key material. */
static void wipe_all_key_material(pw_tls_engine_t* eng) {
    wipe_handshake_secrets(eng);
    secure_zero(eng->read.key,         sizeof(eng->read.key));
    secure_zero(eng->read.static_iv,   sizeof(eng->read.static_iv));
    eng->read.seq = 0;
    secure_zero(eng->write.key,        sizeof(eng->write.key));
    secure_zero(eng->write.static_iv,  sizeof(eng->write.static_iv));
    eng->write.seq = 0;
    eng->keys_installed = 0;
}

/* Mark the engine as having a specific class of pending fatal error.
 * Does NOT change state — the centralised fatal handlers in
 * pw_tls_step transition to PW_TLS_ST_FAILED and consult last_err.
 * If a sub-function sets a more-specific err (AUTH/INTERNAL/OVERFLOW)
 * the centralised handler honours it; otherwise it defaults to
 * PROTOCOL. Idempotent on the more-specific class. */
static inline void engine_mark_err(pw_tls_engine_t* eng, pw_tls_err_t e) {
    /* Do NOT downgrade an already-set specific error. */
    if (eng->last_err == PW_TLS_ERR_NONE) eng->last_err = e;
}

/* Drive the server-side handshake: parse one inbound ClientHello,
 * compute the server's ECDHE keypair + handshake secrets, install
 * handshake-traffic keys for both directions, emit a plaintext
 * ServerHello record into TX. State remains HANDSHAKE; hs_phase
 * advances to AFTER_SH_KEYS.
 *
 * IMPORTANT (RFC 8446 §7.4.2 + low-order-share defence):
 * we MUST NOT queue any bytes into TX until AFTER the X25519 shared
 * secret has been verified non-zero. Otherwise a hostile client
 * sending a low-order pubkey would extract a valid-looking
 * ServerHello before we abort, leaking server-random and our pubkey.
 *
 * Returns 1 on transition (CH consumed, SH queued), 0 on need-more-bytes
 * or not-configured, -1 on fatal protocol error (caller marks FAILED). */
static int try_drive_handshake_server(pw_tls_engine_t* eng) {
    if (!eng->configured) return 0;
    if (eng->hs_phase != PW_TLS_HS_WAIT_CH) return 0;

    /* Need at least the 5-byte record header. */
    if (eng->rx_len < TLS13_RECORD_HEADER_LEN) return 0;

    /* Plain TLSPlaintext envelope: type=handshake (22),
     * legacy_record_version per RFC 8446 §5.1 — first ClientHello
     * commonly uses 0x0301 (TLS 1.0) for backwards-compat with
     * middleboxes; 0x0303 (TLS 1.2) is also allowed. */
    if (eng->rx_buf[0] != TLS_CT_HANDSHAKE) return -1;
    if (eng->rx_buf[1] != 0x03)             return -1;
    if (eng->rx_buf[2] != 0x01 && eng->rx_buf[2] != 0x03) return -1;

    uint16_t rec_len = ((uint16_t)eng->rx_buf[3] << 8) | eng->rx_buf[4];
    if (rec_len == 0 || rec_len > TLS13_MAX_PLAINTEXT) return -1;
    size_t total = TLS13_RECORD_HEADER_LEN + rec_len;
    if (total > PW_TLS_BUF_CAP)             return -1;
    if (eng->rx_len < total)                return 0;

    /* The record body must be exactly one ClientHello handshake msg.
     * We rely on tls13_parse_client_hello to enforce that the inner
     * 24-bit handshake length matches the remainder. */
    const uint8_t* hs_msg = eng->rx_buf + TLS13_RECORD_HEADER_LEN;
    size_t         hs_len = rec_len;

    tls13_client_hello_t ch;
    if (tls13_parse_client_hello(hs_msg, hs_len, &ch) != 0) return -1;
    if (!ch.offers_tls13)        return -1;
    if (!ch.offers_chacha_poly)  return -1;
    if (!ch.offers_x25519)       return -1;

    /* ---- PSK acceptance (RFC 8446 §4.2.11) ---------------------
     * Try to resume only if (a) a ticket store is attached, (b) the
     * client offered pre_shared_key + psk_dhe_ke. Walk the offers in
     * order and accept the FIRST match whose binder verifies. */
    eng->resumed                = 0;
    eng->selected_psk_identity  = -1;
    secure_zero(eng->selected_psk, sizeof(eng->selected_psk));
    if (eng->ticket_store && ch.psk_present && ch.psk_dhe_ke_offered) {
        for (unsigned i = 0; i < ch.psk_offer_count
                          && i < TLS13_PSK_MAX_OFFERS; i++) {
            const uint8_t* id_bytes = hs_msg + ch.psk_id_off[i];
            size_t         id_len   = ch.psk_id_len[i];
            pw_tls_ticket_t* t = pw_tls_ticket_store_lookup(
                eng->ticket_store, id_bytes, id_len, eng->now_ms);
            if (!t) continue;

            /* Hash the partial CH (everything before binders<>). */
            uint8_t partial_hash[32];
            sha256(hs_msg, ch.psk_partial_ch_off, partial_hash);

            uint8_t es[32], bk[32], expected[32];
            if (tls13_compute_early_secret(t->psk, 32, es) != 0
                || tls13_compute_binder_key(es, 0 /*resumption*/, bk) != 0
                || tls13_compute_psk_binder(bk, partial_hash, expected) != 0) {
                secure_zero(es, sizeof(es));
                secure_zero(bk, sizeof(bk));
                secure_zero(partial_hash, sizeof(partial_hash));
                continue;
            }

            const uint8_t* offered_binder = hs_msg + ch.psk_binder_off[i];
            size_t         binder_len     = ch.psk_binder_len[i];
            int match = 0;
            if (binder_len == 32) {
                uint8_t acc = 0;
                for (size_t k = 0; k < 32; k++) acc |= (uint8_t)(expected[k] ^ offered_binder[k]);
                match = (acc == 0);
            }
            secure_zero(es,           sizeof(es));
            secure_zero(bk,           sizeof(bk));
            secure_zero(expected,     sizeof(expected));
            secure_zero(partial_hash, sizeof(partial_hash));

            if (!match) continue;

            eng->resumed               = 1;
            eng->selected_psk_identity = (int)i;
            memcpy(eng->selected_psk, t->psk, 32);

            /* Mark the ticket consumed unconditionally on successful
             * binder match. RFC 8446 §4.6.1 + §8: a server SHOULD
             * treat tickets as single-use to bound replay windows;
             * doing this BEFORE the 0-RTT branch closes a TOCTOU
             * where a non-0-RTT resumption would otherwise leave
             * the ticket replayable in a future handshake. */
            (void)pw_tls_ticket_consume_for_0rtt(t);

            /* 0-RTT acceptance: client must have sent early_data AND
             * the ticket must permit it. We only accept 0-RTT for the
             * FIRST offered identity (RFC 8446 §4.2.10), which is the
             * one we matched at i=0. Note: the ticket has already been
             * marked used above, so can_early_data() is checked against
             * the pre-consume snapshot via the local flags we recorded. */
            if (i == 0 && ch.offers_early_data
                && t->max_early_data > 0) {
                eng->early_data_accepted = 1;
                eng->early_data_max      = t->max_early_data;
                eng->early_data_seen     = 0;
            }
            break;
        }
    }

    /* Full handshake requires ed25519 for the CertificateVerify. A
     * resumption handshake skips Cert+CV entirely so this requirement
     * is dropped. */
    if (!eng->resumed && !ch.offers_ed25519) return -1;

    /* Generate server randomness and X25519 ephemeral keypair. */
    if (eng->rng_fn(eng->rng_user, eng->server_random, 32) != 0) {
        engine_mark_err(eng, PW_TLS_ERR_INTERNAL);
        return -1;
    }
    if (eng->rng_fn(eng->rng_user, eng->eph_priv,      32) != 0) {
        secure_zero(eng->eph_priv, sizeof(eng->eph_priv));
        engine_mark_err(eng, PW_TLS_ERR_INTERNAL);
        return -1;
    }
    /* RFC 7748 §5 clamping. */
    eng->eph_priv[0]  &= 248;
    eng->eph_priv[31] &= 127;
    eng->eph_priv[31] |= 64;
    x25519(eng->eph_pub, eng->eph_priv, X25519_BASE_POINT);

    /* Compute the ECDHE shared secret BEFORE building / queueing SH.
     * This way a low-order pubkey from a hostile client never gets a
     * SH back. (RFC 8446 §7.4.2) */
    uint8_t shared[32];
    x25519(shared, eng->eph_priv, ch.ecdhe_pubkey);
    {
        uint8_t acc = 0;
        for (size_t i = 0; i < 32; i++) acc |= shared[i];
        if (acc == 0) {
            secure_zero(shared, sizeof(shared));
            secure_zero(eng->eph_priv, sizeof(eng->eph_priv));
            return -1;
        }
    }

    /* Build SH into a stack scratch buffer (ServerHello max ~130 B). */
    uint8_t sh_msg[256];
    int sh_len = tls13_build_server_hello_psk(sh_msg, sizeof(sh_msg),
                                              eng->server_random,
                                              eng->eph_pub,
                                              ch.legacy_session_id,
                                              ch.legacy_session_id_len,
                                              eng->resumed
                                                ? eng->selected_psk_identity
                                                : -1);
    if (sh_len <= 0) {
        secure_zero(shared, sizeof(shared));
        secure_zero(eng->eph_priv, sizeof(eng->eph_priv));
        return -1;
    }

    /* Bounds-check TX before any state mutation. SH wire size is
     * 5 (record header) + sh_len (handshake msg). */
    size_t need = TLS13_RECORD_HEADER_LEN + (size_t)sh_len;
    if (need > PW_TLS_BUF_CAP - eng->tx_len) {
        secure_zero(shared, sizeof(shared));
        secure_zero(eng->eph_priv, sizeof(eng->eph_priv));
        return -1;
    }

    /* Feed transcript with CH and SH (handshake msg portions only;
     * the 5-byte record headers are NOT part of the transcript). */
    tls13_transcript_init(&eng->transcript);
    tls13_transcript_update(&eng->transcript, hs_msg, hs_len);
    tls13_transcript_update(&eng->transcript, sh_msg, (size_t)sh_len);

    /* Snapshot transcript hash = H(CH || SH). */
    uint8_t th[32];
    tls13_transcript_snapshot(&eng->transcript, th);

    /* Derive the handshake secrets. PSK-aware variant on resumption,
     * zero-PSK variant otherwise. */
    int sec_rc;
    if (eng->resumed) {
        sec_rc = tls13_compute_handshake_secrets_psk(
                     eng->selected_psk, 32, shared, th,
                     eng->handshake_secret,
                     eng->cs_handshake_secret,
                     eng->ss_handshake_secret);
    } else {
        sec_rc = tls13_compute_handshake_secrets(shared, th,
                     eng->handshake_secret,
                     eng->cs_handshake_secret,
                     eng->ss_handshake_secret);
    }
    if (sec_rc != 0) {
        secure_zero(shared, sizeof(shared));
        secure_zero(th, sizeof(th));
        wipe_handshake_secrets(eng);
        return -1;
    }
    secure_zero(shared, sizeof(shared));
    secure_zero(th, sizeof(th));

    /* Install per-direction (key, iv). As server we DECRYPT the
     * client->server traffic and ENCRYPT the server->client traffic.
     *
     * 0-RTT case: when early data was accepted, the read direction
     * must initially decrypt with c_e_traffic-derived keys (the
     * client's early data records arrive after CH and BEFORE the
     * client switches to handshake-traffic keys). We stash the
     * cs_handshake-derived (k,iv) on the engine so we can swap to
     * them after we see EndOfEarlyData. */
    {
        uint8_t k[32], iv[12];
        tls13_derive_traffic_keys(eng->cs_handshake_secret, k, iv);
        if (eng->early_data_accepted) {
            memcpy(eng->saved_hs_read_key, k,  32);
            memcpy(eng->saved_hs_read_iv,  iv, 12);

            /* Compute c_e_traffic = Derive-Secret(early_secret,
             *   "c e traffic", H(CH only)). H(CH) is what we already
             * folded into the transcript before SH; redo a snapshot
             * over just the CH bytes via a clean transcript. */
            tls13_transcript_t ts_ch_only;
            tls13_transcript_init(&ts_ch_only);
            tls13_transcript_update(&ts_ch_only, hs_msg, hs_len);
            uint8_t th_ch[32];
            tls13_transcript_snapshot(&ts_ch_only, th_ch);

            uint8_t es[32], cets[32];
            int ed_rc = tls13_compute_early_secret(eng->selected_psk, 32, es);
            if (ed_rc == 0) ed_rc = tls13_compute_client_early_traffic_secret(
                                        es, th_ch, cets);
            if (ed_rc == 0) tls13_derive_traffic_keys(cets, k, iv);
            secure_zero(es,   sizeof(es));
            secure_zero(cets, sizeof(cets));
            secure_zero(th_ch, sizeof(th_ch));

            if (ed_rc != 0) {
                /* Roll back: refuse 0-RTT, fall through to normal
                 * cs_handshake install. */
                eng->early_data_accepted = 0;
                eng->early_data_max      = 0;
                tls13_derive_traffic_keys(eng->cs_handshake_secret, k, iv);
            } else {
                eng->early_data_phase = 1;  /* ACTIVE */
            }
        }
        memcpy(eng->read.key,        k,  32);
        memcpy(eng->read.static_iv,  iv, 12);
        eng->read.seq = 0;

        tls13_derive_traffic_keys(eng->ss_handshake_secret, k, iv);
        memcpy(eng->write.key,       k,  32);
        memcpy(eng->write.static_iv, iv, 12);
        eng->write.seq = 0;

        secure_zero(k,  sizeof(k));
        secure_zero(iv, sizeof(iv));
    }

    /* Eph priv is no longer needed (shared already derived + wiped). */
    secure_zero(eng->eph_priv, sizeof(eng->eph_priv));

    /* Now — and only now — commit the SH plaintext record into TX. */
    {
        uint8_t* out = eng->tx_buf + eng->tx_len;
        out[0] = TLS_CT_HANDSHAKE;
        out[1] = 0x03; out[2] = 0x03;            /* legacy_record_version */
        out[3] = (uint8_t)((unsigned)sh_len >> 8);
        out[4] = (uint8_t)((unsigned)sh_len & 0xff);
        memcpy(out + TLS13_RECORD_HEADER_LEN, sh_msg, (size_t)sh_len);
        eng->tx_len += need;
        eng->records_out++;
    }

    eng->keys_installed = 1;
    eng->hs_phase       = PW_TLS_HS_AFTER_SH_KEYS;
    /* state stays PW_TLS_ST_HANDSHAKE — the encrypted EE/Cert/CV/sFin
     * flight is emitted by try_emit_server_flight on the next step
     * (or this same step, see the loop in pw_tls_step). */

    /* Slide RX past the consumed CH record. */
    buf_shift(eng->rx_buf, &eng->rx_len, total);
    return 1;
}

/* Seal a single handshake-type message into TX as an encrypted record
 * using eng->write (currently the server handshake-traffic key). The
 * `msg` bytes are the raw handshake message (header + body); they are
 * also fed into the running transcript before being sealed.
 *
 * Returns 0 on success, -1 on overflow / seal error. */
static int seal_one_handshake_msg(pw_tls_engine_t* eng,
                                  const uint8_t* msg, size_t msg_len) {
    size_t need = TLS13_RECORD_HEADER_LEN + msg_len + 1 + TLS13_AEAD_TAG_LEN;
    if (need > PW_TLS_BUF_CAP - eng->tx_len) return -1;

    tls13_transcript_update(&eng->transcript, msg, msg_len);

    size_t wrote = tls13_seal_record(&eng->write,
                                     TLS_CT_HANDSHAKE,
                                     TLS_CT_APPLICATION_DATA,
                                     msg, msg_len,
                                     eng->tx_buf + eng->tx_len,
                                     PW_TLS_BUF_CAP - eng->tx_len);
    if (wrote == 0) return -1;
    eng->tx_len += wrote;
    eng->records_out++;
    return 0;
}

/* Emit the server's encrypted handshake flight: EE, Certificate,
 * CertificateVerify, server Finished — all sealed under the server
 * handshake-traffic key. After emission, derive + cache application
 * traffic secrets, and transition hs_phase to AFTER_SF_AWAIT_CF.
 *
 * Returns 1 on transition, 0 if nothing to do (wrong phase) or TX
 * is too full to fit the flight, -1 on fatal error. */
static int try_emit_server_flight(pw_tls_engine_t* eng) {
    if (eng->hs_phase != PW_TLS_HS_AFTER_SH_KEYS) return 0;
    if (!eng->configured) return -1;

    /* Conservative TX-room check: the four messages are all small
     * except Certificate, which is bounded by the configured chain
     * size. Sum: 4*(record_hdr+type+tag) + EE + Cert + CV + Fin
     * worst case. We compute precise sizes below; if any seal
     * fails on bounds we return -1 and FAILED. */

    /* ---- EE ---- */
    {
        uint8_t ee[16];
        int ee_len = tls13_build_encrypted_extensions_ex(
                         ee, sizeof(ee), eng->early_data_accepted);
        if (ee_len <= 0) return -1;
        if (seal_one_handshake_msg(eng, ee, (size_t)ee_len) != 0) return -1;
    }

    /* ---- Certificate + CertificateVerify (skipped on resumption,
     *      RFC 8446 §4.6.1: server MUST NOT send Certificate or
     *      CertificateVerify when resuming via PSK). ----*/
    if (!eng->resumed) {
    /* ---- Certificate ---- */
    {
        /* Compute the exact certificate message size up front; we
         * already validated this fits in PW_TLS_ENGINE_CERT_MSG_MAX
         * at configure_server time, so this stack buffer is safe. */
        size_t cert_msg_size = 4 + 1 + 3;
        for (unsigned i = 0; i < eng->n_certs; i++) {
            cert_msg_size += 3 + eng->cert_lens[i] + 2;
        }
        if (cert_msg_size > PW_TLS_ENGINE_CERT_MSG_MAX) return -1;

        uint8_t cert_msg[PW_TLS_ENGINE_CERT_MSG_MAX];
        int cert_len = tls13_build_certificate(cert_msg, sizeof(cert_msg),
                                               eng->cert_chain_der,
                                               eng->cert_lens,
                                               eng->n_certs);
        if (cert_len <= 0) return -1;
        if (seal_one_handshake_msg(eng, cert_msg, (size_t)cert_len) != 0) return -1;
    }

    /* ---- CertificateVerify ---- */
    {
        /* CV signs the transcript hash through Certificate (the prior
         * snapshot we just took before sealing), so snapshot now. */
        uint8_t th_through_cert[32];
        tls13_transcript_snapshot(&eng->transcript, th_through_cert);

        uint8_t cv[128];
        int cv_len = tls13_build_certificate_verify(cv, sizeof(cv),
                                                    th_through_cert,
                                                    eng->seed_ed25519);
        secure_zero(th_through_cert, sizeof(th_through_cert));
        if (cv_len <= 0) return -1;
        if (seal_one_handshake_msg(eng, cv, (size_t)cv_len) != 0) return -1;
    }
    } /* end if (!eng->resumed) */

    /* ---- server Finished ---- */
    {
        /* server Finished verify_data = HMAC(server_finished_key,
         * H(CH..CV)). After sealing CV the transcript is at H(CH..CV). */
        uint8_t th_through_cv[32];
        tls13_transcript_snapshot(&eng->transcript, th_through_cv);

        uint8_t verify_data[32];
        if (tls13_compute_finished(eng->ss_handshake_secret,
                                   th_through_cv,
                                   verify_data) != 0) {
            secure_zero(th_through_cv, sizeof(th_through_cv));
            return -1;
        }
        secure_zero(th_through_cv, sizeof(th_through_cv));

        uint8_t fin[4 + 32];
        int fin_len = tls13_build_finished(fin, sizeof(fin), verify_data);
        secure_zero(verify_data, sizeof(verify_data));
        if (fin_len <= 0) return -1;
        if (seal_one_handshake_msg(eng, fin, (size_t)fin_len) != 0) return -1;
    }

    /* ---- Derive + cache application secrets (T4 = H(CH..sFin)) ---- */
    {
        uint8_t th_through_sf[32];
        tls13_transcript_snapshot(&eng->transcript, th_through_sf);

        if (tls13_compute_application_secrets(eng->handshake_secret,
                                              th_through_sf,
                                              eng->master_secret,
                                              eng->cs_app_traffic_secret,
                                              eng->ss_app_traffic_secret) != 0) {
            secure_zero(th_through_sf, sizeof(th_through_sf));
            return -1;
        }
        secure_zero(th_through_sf, sizeof(th_through_sf));
    }

    eng->hs_phase = PW_TLS_HS_AFTER_SF_AWAIT_CF;
    return 1;
}

/* Try to consume one inbound record while in AFTER_SF_AWAIT_CF phase.
 *
 * Three things can come in here:
 *   1) A dummy ChangeCipherSpec record (RFC 8446 §D.4) — silently
 *      consumed. Plain TLSPlaintext, content_type=20, body=0x01.
 *   2) An encrypted handshake record containing the client Finished.
 *      Decrypt with cs_handshake_traffic key, verify, transition to APP.
 *   3) Anything else -> protocol error.
 *
 * Returns 1 on transition (cFin verified, state→APP), 0 on
 * need-more-bytes, -1 on protocol/auth error. */
static int try_recv_client_finished(pw_tls_engine_t* eng) {
    if (eng->hs_phase != PW_TLS_HS_AFTER_SF_AWAIT_CF) return 0;
    if (eng->rx_len < TLS13_RECORD_HEADER_LEN) return 0;

    /* Compute snapshot transcript hash through server Finished BEFORE
     * we feed the client Finished into the transcript (we don't, but
     * staying explicit helps). The cs_finished verify_data is HMAC
     * over T4 = H(CH..sFin). */

    /* Peek at the record header. */
    uint8_t  ct      = eng->rx_buf[0];
    uint16_t rec_len = ((uint16_t)eng->rx_buf[3] << 8) | eng->rx_buf[4];
    if (eng->rx_buf[1] != 0x03) return -1;
    if (eng->rx_buf[2] != 0x03 && eng->rx_buf[2] != 0x01) return -1;
    if (rec_len == 0 || rec_len > TLS13_MAX_CIPHERTEXT) return -1;
    size_t total = TLS13_RECORD_HEADER_LEN + rec_len;
    if (total > PW_TLS_BUF_CAP) return -1;
    if (eng->rx_len < total) return 0;

    /* Dummy ChangeCipherSpec — RFC 8446 §D.4 compat-mode. Always
     * exactly one byte of value 0x01. Silently drop and signal the
     * step loop to retry (the next record may be the cFin). */
    if (ct == TLS_CT_CHANGE_CIPHER_SPEC) {
        if (rec_len != 1 || eng->rx_buf[TLS13_RECORD_HEADER_LEN] != 0x01) return -1;
        buf_shift(eng->rx_buf, &eng->rx_len, total);
        return 1;   /* made progress; loop will re-enter and process cFin */
    }

    /* Otherwise it must be the encrypted client Finished. The wire
     * outer type for any encrypted TLS 1.3 record is APPLICATION_DATA. */
    if (ct != TLS_CT_APPLICATION_DATA) return -1;

    tls_content_type_t inner = TLS_CT_INVALID;
    uint8_t* pt = NULL;
    size_t   pt_len = 0;
    if (tls13_open_record(&eng->read, eng->rx_buf, total,
                          &inner, &pt, &pt_len) != 0) {
        engine_mark_err(eng, PW_TLS_ERR_AUTH);
        return -1;
    }

    /* 0-RTT: while early_data_phase==ACTIVE, the read direction holds
     * c_e_traffic. We expect either an application_data record (early
     * plaintext) or a single EndOfEarlyData handshake message. The
     * cFin will only arrive AFTER EOED, when we've swapped read keys
     * back to handshake-traffic. */
    if (eng->early_data_phase == 1) {
        if (inner == TLS_CT_APPLICATION_DATA) {
            /* Surface early-data plaintext into APP_IN, capped at
             * eng->early_data_max. Plaintext is already in
             * eng->rx_buf[..]; copy into app_in_buf. */
            if (eng->early_data_seen + pt_len > eng->early_data_max) {
                engine_mark_err(eng, PW_TLS_ERR_PROTOCOL);
                return -1;
            }
            if (eng->app_in_len + pt_len > PW_TLS_BUF_CAP) {
                /* APP_IN full — caller must drain before more early
                 * data can be surfaced. We cannot rewind dir->seq
                 * (already bumped during open), so we must NOT
                 * silently partial-copy: doing so under-counts
                 * early_data_seen and lets a malicious client push
                 * past max_early_data. Treat as a fatal overflow;
                 * caller is expected to size APP_IN >= max early_data
                 * the ticket permits. */
                engine_mark_err(eng, PW_TLS_ERR_OVERFLOW);
                return -1;
            }
            memcpy(eng->app_in_buf + eng->app_in_len, pt, pt_len);
            eng->app_in_len      += pt_len;
            eng->early_data_seen += (uint32_t)pt_len;
            buf_shift(eng->rx_buf, &eng->rx_len, total);
            return 1;   /* loop will re-enter and look for next record */
        }
        if (inner == TLS_CT_HANDSHAKE) {
            /* Must be EndOfEarlyData: type=0x05, length=0 (4 bytes). */
            if (pt_len != 4) return -1;
            if (pt[0] != 0x05) return -1;
            if (pt[1] != 0 || pt[2] != 0 || pt[3] != 0) return -1;
            /* Feed EOED into the transcript so cFin verify works. */
            tls13_transcript_update(&eng->transcript, pt, pt_len);
            /* Swap read keys back to cs_handshake. */
            memcpy(eng->read.key,       eng->saved_hs_read_key, 32);
            memcpy(eng->read.static_iv, eng->saved_hs_read_iv,  12);
            eng->read.seq = 0;
            secure_zero(eng->saved_hs_read_key, 32);
            secure_zero(eng->saved_hs_read_iv,  12);
            eng->early_data_phase = 2;  /* DONE */
            buf_shift(eng->rx_buf, &eng->rx_len, total);
            return 1;
        }
        /* Anything else under c_e_traffic is a protocol error. */
        return -1;
    }

    if (inner != TLS_CT_HANDSHAKE)            return -1;
    /* Finished message header: 0x14 + 24-bit length = 32. */
    if (pt_len != 4 + 32)                     return -1;
    if (pt[0] != 0x14)                        return -1;
    if (pt[1] != 0x00 || pt[2] != 0x00 || pt[3] != 0x20) return -1;

    /* Verify against transcript-through-server-Finished + the client
     * handshake-traffic secret. */
    uint8_t th_through_sf[32];
    tls13_transcript_snapshot(&eng->transcript, th_through_sf);
    if (tls13_verify_finished(eng->cs_handshake_secret,
                              th_through_sf,
                              pt + 4) != 0) {
        secure_zero(th_through_sf, sizeof(th_through_sf));
        engine_mark_err(eng, PW_TLS_ERR_AUTH);
        return -1;
    }
    secure_zero(th_through_sf, sizeof(th_through_sf));

    /* Feed the client Finished into the transcript. We need the
     * transcript-through-cFin both for the RFC 8446 §7.1
     * resumption_master_secret derivation and for any post-handshake
     * messages that hash into the same context. */
    tls13_transcript_update(&eng->transcript, pt, pt_len);

    /* Derive resumption_master_secret = Derive-Secret(master_secret,
     * "res master", H(CH..cFin)). Persist on the engine for the
     * NewSessionTicket builder; master_secret is wiped immediately
     * afterwards. */
    {
        uint8_t th_through_cf[32];
        tls13_transcript_snapshot(&eng->transcript, th_through_cf);
        if (tls13_compute_resumption_master_secret(
                eng->master_secret, th_through_cf,
                eng->resumption_master_secret) == 0) {
            eng->has_rms = 1;
        }
        secure_zero(th_through_cf, sizeof(th_through_cf));
    }

    /* Switch read+write to application-traffic keys. */
    {
        uint8_t k[32], iv[12];
        tls13_derive_traffic_keys(eng->cs_app_traffic_secret, k, iv);
        memcpy(eng->read.key,        k,  32);
        memcpy(eng->read.static_iv,  iv, 12);
        eng->read.seq = 0;

        tls13_derive_traffic_keys(eng->ss_app_traffic_secret, k, iv);
        memcpy(eng->write.key,       k,  32);
        memcpy(eng->write.static_iv, iv, 12);
        eng->write.seq = 0;

        secure_zero(k,  sizeof(k));
        secure_zero(iv, sizeof(iv));
    }

    /* Wipe handshake-only secrets. master_secret has already been
     * consumed by the RMS derivation above. (Application traffic
     * secrets stay in case we ever implement KeyUpdate.) */
    secure_zero(eng->handshake_secret,    sizeof(eng->handshake_secret));
    secure_zero(eng->cs_handshake_secret, sizeof(eng->cs_handshake_secret));
    secure_zero(eng->ss_handshake_secret, sizeof(eng->ss_handshake_secret));
    secure_zero(eng->master_secret,       sizeof(eng->master_secret));

    eng->state    = PW_TLS_ST_APP;
    /* hs_phase remains AFTER_SF_AWAIT_CF — but it's no longer
     * meaningful in APP state. */

    /* Slide RX past consumed cFin record. */
    buf_shift(eng->rx_buf, &eng->rx_len, total);
    return 1;
}

int pw_tls_step(pw_tls_engine_t* eng) {
    if (!eng) return -1;
    if (eng->state == PW_TLS_ST_FAILED) return -1;
    if (eng->state == PW_TLS_ST_HANDSHAKE) {
        /* Drive the handshake forward. Each helper is a no-op outside
         * its own phase, so calling them in order walks WAIT_CH ->
         * AFTER_SH_KEYS -> AFTER_SF_AWAIT_CF -> APP without needing a
         * dispatch table. */
        for (int spin = 0; spin < 8; spin++) {
            int rc = try_drive_handshake_server(eng);
            if (rc < 0) goto fail;
            if (rc > 0) continue;

            rc = try_emit_server_flight(eng);
            if (rc < 0) goto fail;
            if (rc > 0) continue;

            rc = try_recv_client_finished(eng);
            if (rc < 0) goto fail;
            if (rc > 0) continue;

            /* No phase made progress this round — wait for more I/O. */
            break;
        }
        return (int)pw_tls_want(eng);

      fail:
        /* On any fatal handshake failure: wipe ALL key material AND
         * drop any partially-emitted bytes from TX. The engine MUST
         * NOT expose half-emitted handshake records to a caller that
         * reads pw_tls_tx_buf after we go FAILED. (Rubber-duck blocker
         * #1 from the Commit B critique.) */
        wipe_all_key_material(eng);
        eng->tx_len     = 0;
        eng->app_in_len = 0;
        eng->state      = PW_TLS_ST_FAILED;
        if (eng->last_err == PW_TLS_ERR_NONE)
            eng->last_err = PW_TLS_ERR_PROTOCOL;
        return -1;
    }

    /* Drain RX -> APP_IN, AT MOST ONE record per step in APP state.
     * Coalescing multiple records' plaintext into APP_IN would force
     * callers to either (a) be aware of TLS record boundaries
     * (defeating the abstraction) or (b) merge requests/responses
     * silently. Stream consumers like pw_conn want one record's
     * worth of plaintext per drain cycle. */
    int rc;
    do {
        if (eng->app_in_len > 0) break;   /* caller must drain first */
        rc = try_open_one(eng);
        if (rc < 0) {
            eng->state = PW_TLS_ST_FAILED;
            if (eng->last_err == PW_TLS_ERR_NONE)
                eng->last_err = PW_TLS_ERR_PROTOCOL;
            return -1;
        }
    } while (rc == 1 && eng->state == PW_TLS_ST_APP);

    /* Drain APP_OUT -> TX, one record at a time, until empty / TX full. */
    do {
        rc = try_seal_one(eng);
        if (rc < 0) {
            eng->state = PW_TLS_ST_FAILED;
            if (eng->last_err == PW_TLS_ERR_NONE)
                eng->last_err = PW_TLS_ERR_INTERNAL;
            return -1;
        }
    } while (rc == 1);

    return (int)pw_tls_want(eng);
}
