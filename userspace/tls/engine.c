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
#include "../crypto/x25519.h"
#include "handshake.h"
#include "keysched.h"
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

/* ----------------------- introspection ----------------------- */

pw_tls_state_t pw_tls_state(const pw_tls_engine_t* eng) {
    return eng ? eng->state : PW_TLS_ST_FAILED;
}

pw_tls_hs_phase_t pw_tls_hs_phase(const pw_tls_engine_t* eng) {
    return eng ? eng->hs_phase : PW_TLS_HS_WAIT_CH;
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

/* Wipe handshake-context secrets after a fatal handshake error. The
 * engine is about to transition to FAILED; the caller will eventually
 * destroy it, but we don't want secrets sitting in memory in the
 * meantime. */
static void wipe_handshake_secrets(pw_tls_engine_t* eng) {
    secure_zero(eng->eph_priv,            sizeof(eng->eph_priv));
    secure_zero(eng->handshake_secret,    sizeof(eng->handshake_secret));
    secure_zero(eng->cs_handshake_secret, sizeof(eng->cs_handshake_secret));
    secure_zero(eng->ss_handshake_secret, sizeof(eng->ss_handshake_secret));
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
    if (!ch.offers_ed25519)      return -1;

    /* Generate server randomness and X25519 ephemeral keypair. */
    if (eng->rng_fn(eng->rng_user, eng->server_random, 32) != 0) return -1;
    if (eng->rng_fn(eng->rng_user, eng->eph_priv,      32) != 0) {
        secure_zero(eng->eph_priv, sizeof(eng->eph_priv));
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
    int sh_len = tls13_build_server_hello(sh_msg, sizeof(sh_msg),
                                          eng->server_random,
                                          eng->eph_pub,
                                          ch.legacy_session_id,
                                          ch.legacy_session_id_len);
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

    /* Derive the handshake secrets. */
    if (tls13_compute_handshake_secrets(shared, th,
                                        eng->handshake_secret,
                                        eng->cs_handshake_secret,
                                        eng->ss_handshake_secret) != 0) {
        secure_zero(shared, sizeof(shared));
        secure_zero(th, sizeof(th));
        wipe_handshake_secrets(eng);
        return -1;
    }
    secure_zero(shared, sizeof(shared));
    secure_zero(th, sizeof(th));

    /* Install per-direction (key, iv). As server we DECRYPT the
     * client->server traffic and ENCRYPT the server->client traffic. */
    {
        uint8_t k[32], iv[12];
        tls13_derive_traffic_keys(eng->cs_handshake_secret, k, iv);
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
    /* state stays PW_TLS_ST_HANDSHAKE — Commit B will emit the
     * encrypted EE/Cert/CV/Finished flight and transition to APP. */

    /* Slide RX past the consumed CH record. */
    buf_shift(eng->rx_buf, &eng->rx_len, total);
    return 1;
}

int pw_tls_step(pw_tls_engine_t* eng) {
    if (!eng) return -1;
    if (eng->state == PW_TLS_ST_FAILED) return -1;
    if (eng->state == PW_TLS_ST_HANDSHAKE) {
        /* Drive the handshake forward. For the spike, only the
         * server-side path is implemented (CH -> SH + install
         * handshake-traffic keys). A client engine without a
         * configure_server will simply no-op here, matching the
         * old behaviour. */
        int rc;
        do {
            rc = try_drive_handshake_server(eng);
            if (rc < 0) {
                wipe_handshake_secrets(eng);
                eng->state = PW_TLS_ST_FAILED;
                return -1;
            }
        } while (rc == 1 && eng->state == PW_TLS_ST_HANDSHAKE
                         && eng->hs_phase == PW_TLS_HS_WAIT_CH);
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
