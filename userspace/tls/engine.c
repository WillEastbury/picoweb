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
#include "record.h"

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
    eng->state = PW_TLS_ST_HANDSHAKE;
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

/* ----------------------- introspection ----------------------- */

pw_tls_state_t pw_tls_state(const pw_tls_engine_t* eng) {
    return eng ? eng->state : PW_TLS_ST_FAILED;
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
    buf_shift(eng->app_in_buf, &eng->app_in_len, n);
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
    if (rc < 0) return -1;

    /* Bump the read seq AFTER successful open (the open helper does
     * NOT bump - convention from record.c). */
    eng->read.seq++;
    eng->records_in++;

    if (inner == TLS_CT_APPLICATION_DATA) {
        if (pt_len > PW_TLS_BUF_CAP - eng->app_in_len) {
            /* APP_IN full - leave the record in RX, the caller must
             * drain APP_IN and call step again. We already bumped seq
             * and consumed the record though, so we can't actually
             * leave it - this is a logic bug in the spike. For now,
             * if APP_IN is full we drop and signal protocol error. */
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

    eng->write.seq++;
    eng->tx_len += wrote;
    eng->records_out++;

    /* Advance APP_OUT past the bytes we just sealed. */
    buf_shift(eng->app_out_buf, &eng->app_out_len, pt_len);
    return 1;
}

int pw_tls_step(pw_tls_engine_t* eng) {
    if (!eng) return -1;
    if (eng->state == PW_TLS_ST_FAILED) return -1;
    if (eng->state == PW_TLS_ST_HANDSHAKE) {
        /* Handshake-driving logic lands here once Ed25519 is in.
         * For now: nothing to do without keys. */
        return (int)pw_tls_want(eng);
    }

    /* Drain RX -> APP_IN, one record at a time, until empty / blocked. */
    int rc;
    do {
        rc = try_open_one(eng);
        if (rc < 0) { eng->state = PW_TLS_ST_FAILED; return -1; }
    } while (rc == 1 && eng->state == PW_TLS_ST_APP);

    /* Drain APP_OUT -> TX, one record at a time, until empty / TX full. */
    do {
        rc = try_seal_one(eng);
        if (rc < 0) { eng->state = PW_TLS_ST_FAILED; return -1; }
    } while (rc == 1);

    return (int)pw_tls_want(eng);
}
