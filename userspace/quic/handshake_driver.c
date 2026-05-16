/* SPDX-License-Identifier: MIT
 * picoweb — QUIC ⇄ TLS 1.3 handshake driver (server-side)
 */
#include "handshake_driver.h"

#include "../tls/handshake.h"
#include "../tls/keysched.h"
#include "../crypto/x25519.h"
#include "../crypto/sha256.h"

#include <string.h>

/* Static scratch sized to comfortably hold the largest single
 * server flight message (Certificate, dominated by the leaf+chain).
 * 4 KiB covers an RSA-2048 ECDSA-mixed chain; we'd need to grow this
 * for true bloated chains. Allocated on the stack of the driver. */
#define DRV_MSG_SCRATCH 4096
#define DRV_HS_BLOB_CAP 8192

static int build_server_flight_handshake_blob(
    uint8_t* out, size_t out_cap, size_t* out_len,
    tls13_transcript_t* trans,
    const quic_server_handshake_inputs_t* in,
    const uint8_t server_hs_traffic_secret[32])
{
    size_t off = 0;
    uint8_t scratch[DRV_MSG_SCRATCH];

    /* ---- EncryptedExtensions ------------------------------------- */
    int ee_n = tls13_build_encrypted_extensions(scratch, sizeof scratch);
    if (ee_n <= 0 || (size_t)ee_n > out_cap - off) return -1;
    memcpy(out + off, scratch, (size_t)ee_n);
    tls13_transcript_update(trans, out + off, (size_t)ee_n);
    off += (size_t)ee_n;

    /* ---- Certificate --------------------------------------------- */
    int cert_n = tls13_build_certificate(scratch, sizeof scratch,
                                         in->cert.chain_der,
                                         in->cert.cert_lens,
                                         in->cert.n_certs);
    if (cert_n <= 0 || (size_t)cert_n > out_cap - off) return -1;
    memcpy(out + off, scratch, (size_t)cert_n);
    tls13_transcript_update(trans, out + off, (size_t)cert_n);
    off += (size_t)cert_n;

    /* ---- CertificateVerify --------------------------------------- */
    /* Snapshot the transcript through Certificate (NOT including CV). */
    uint8_t th_thru_cert[32];
    tls13_transcript_snapshot(trans, th_thru_cert);

    int cv_n = tls13_build_certificate_verify(scratch, sizeof scratch,
                                              th_thru_cert,
                                              in->cert.ed25519_seed);
    if (cv_n <= 0 || (size_t)cv_n > out_cap - off) return -1;
    memcpy(out + off, scratch, (size_t)cv_n);
    tls13_transcript_update(trans, out + off, (size_t)cv_n);
    off += (size_t)cv_n;

    /* ---- Finished ------------------------------------------------- */
    /* Snapshot through CV — Finished's verify_data is over this. */
    uint8_t th_thru_cv[32];
    tls13_transcript_snapshot(trans, th_thru_cv);

    uint8_t verify_data[32];
    if (tls13_compute_finished(server_hs_traffic_secret,
                               th_thru_cv, verify_data) != 0) return -1;

    int fin_n = tls13_build_finished(scratch, sizeof scratch, verify_data);
    if (fin_n <= 0 || (size_t)fin_n > out_cap - off) return -1;
    memcpy(out + off, scratch, (size_t)fin_n);
    tls13_transcript_update(trans, out + off, (size_t)fin_n);
    off += (size_t)fin_n;

    *out_len = off;
    return 0;
}

int quic_server_drive_handshake(quic_conn_t* c,
                                const quic_server_handshake_inputs_t* in)
{
    if (!c || !in) return -1;
    if (!in->server_priv_x25519 || !in->server_random) return -1;
    if (!in->cert.chain_der || !in->cert.cert_lens ||
        in->cert.n_certs == 0 || !in->cert.ed25519_seed) return -1;

    /* ---- 1. Extract + validate ClientHello ----------------------- */
    tls13_client_hello_t ch;
    quic_transport_params_t peer_tp;
    int xrc = quic_conn_initial_extract_client_hello(c, &ch, &peer_tp);
    if (xrc != 1) return -1;
    if (!ch.offers_tls13)    return -1;
    if (!ch.offers_x25519)   return -1;
    if (!ch.offers_ed25519)  return -1;

    /* ---- 2. ECDHE: derive shared + our pubkey -------------------- */
    uint8_t our_pub[32];
    x25519(our_pub, in->server_priv_x25519, X25519_BASE_POINT);
    uint8_t ecdhe_shared[32];
    x25519(ecdhe_shared, in->server_priv_x25519, ch.ecdhe_pubkey);

    /* All-zero shared = degenerate small-subgroup peer pub. */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= ecdhe_shared[i];
    if (!nonzero) return -1;

    /* ---- 3. Build ServerHello ------------------------------------ */
    /* The conn's tx_initial holds aliases — we need a buffer that
     * outlives this function (until the bytes are emitted). The
     * embedder owns the SH bytes in a per-conn scratch they pass in;
     * for the spike we live-allocate on conn via a dedicated buffer. */
    /* Use the existing tx_initial mechanism: the alias model means
     * `c` must hold a stable pointer. We stash the SH bytes inside a
     * caller-supplied per-conn scratch that we reach via a fixed
     * arena on the conn struct (see drv_initial_blob below). */
    static const size_t SH_MAX = 256;  /* SH is < 200 bytes for our spike. */
    if (sizeof(c->drv_initial_blob) < SH_MAX) return -1;

    int sh_n = tls13_build_server_hello(c->drv_initial_blob,
                                        sizeof c->drv_initial_blob,
                                        in->server_random, our_pub,
                                        ch.legacy_session_id,
                                        ch.legacy_session_id_len);
    if (sh_n <= 0) return -1;
    c->drv_initial_blob_len = (size_t)sh_n;

    /* ---- 4. Transcript hash through SH --------------------------- */
    tls13_transcript_t trans;
    tls13_transcript_init(&trans);
    if (!ch.raw || ch.raw_len == 0) return -1;
    tls13_transcript_update(&trans, ch.raw, ch.raw_len);
    tls13_transcript_update(&trans, c->drv_initial_blob,
                            c->drv_initial_blob_len);
    uint8_t th_thru_sh[32];
    tls13_transcript_snapshot(&trans, th_thru_sh);

    /* ---- 5. Compute handshake secrets ---------------------------- */
    uint8_t hs_secret[32], c_hs_ts[32], s_hs_ts[32];
    if (tls13_compute_handshake_secrets(ecdhe_shared, th_thru_sh,
                                        hs_secret, c_hs_ts, s_hs_ts) != 0)
        return -1;

    /* ---- 6. Install Handshake-epoch keys on conn ----------------- */
    /* Server tx = server_hs_traffic_secret;
     * Server rx = client_hs_traffic_secret. */
    if (quic_conn_install_handshake_secrets(c, s_hs_ts, c_hs_ts, 32) != 0)
        return -1;

    /* ---- 7. Build EE/Cert/CV/Fin into Handshake-epoch blob ------- */
    if (build_server_flight_handshake_blob(c->drv_handshake_blob,
                                           sizeof c->drv_handshake_blob,
                                           &c->drv_handshake_blob_len,
                                           &trans, in, s_hs_ts) != 0)
        return -1;

    /* Snapshot transcript through server Finished — needed by 5e7. */
    tls13_transcript_snapshot(&trans, c->transcript_hash_thru_server_fin);
    memcpy(c->handshake_secret,                hs_secret, 32);
    memcpy(c->client_handshake_traffic_secret, c_hs_ts,   32);
    memcpy(c->server_handshake_traffic_secret, s_hs_ts,   32);
    c->have_handshake_state = 1;

    /* ---- 8. Hand the bytes to the conn tx pipelines -------------- */
    quic_conn_initial_tx_set_pending(c, c->drv_initial_blob,
                                     c->drv_initial_blob_len);
    quic_conn_handshake_tx_set_pending(c, c->drv_handshake_blob,
                                       c->drv_handshake_blob_len);
    return 0;
}
