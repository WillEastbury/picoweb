/* SPDX-License-Identifier: MIT
 * picoweb — QUIC ⇄ TLS 1.3 handshake driver (server-side, wave 5 §5e6)
 *
 * This module is the missing link between the QUIC connection state
 * machine (quic_conn_t) and the standalone TLS 1.3 primitives in
 * userspace/tls/. Its single entry point — quic_server_drive_handshake
 * — consumes a ClientHello already buffered in the conn's Initial-epoch
 * rx reassembler (quic_conn_initial_extract_client_hello path) and
 * emits the entire server flight:
 *
 *   Initial epoch   :  ServerHello
 *   Handshake epoch :  EncryptedExtensions
 *                      Certificate
 *                      CertificateVerify
 *                      Finished
 *
 * The handshake-epoch packet keys are derived from the freshly
 * computed handshake_traffic_secrets and installed on the conn via
 * quic_conn_install_handshake_secrets. The pending CRYPTO byte
 * streams are queued via quic_conn_initial_tx_set_pending and
 * quic_conn_handshake_tx_set_pending; the embedder is then free to
 * call quic_conn_emit_initial / quic_conn_emit_handshake repeatedly
 * to package the bytes into one or more datagrams.
 *
 * We do NOT yet drive the post-Finished phases — client Finished
 * verification and 1-RTT key derivation belong to phase 5e7. The
 * handshake_secret + transcript-through-server-Finished snapshot
 * needed for those steps are persisted on `quic_conn_t` via the
 * fields populated here.
 *
 * Caller-supplied material:
 *   - server_priv_x25519[32]  : ephemeral private scalar
 *   - server_random[32]       : fresh server random (CSPRNG)
 *   - cert_chain_der + lens   : DER X.509 chain (leaf first)
 *   - cert_ed25519_seed[32]   : raw Ed25519 seed for the leaf
 *
 * Spike scope: ed25519-only certificates, X25519-only key share, no
 * PSK / 0-RTT, no HelloRetryRequest. Other shapes return -1 with no
 * conn-state mutation.
 */
#ifndef PICOWEB_USERSPACE_QUIC_HANDSHAKE_DRIVER_H
#define PICOWEB_USERSPACE_QUIC_HANDSHAKE_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#include "conn.h"

typedef struct {
    const uint8_t* chain_der;
    const size_t*  cert_lens;
    unsigned       n_certs;
    const uint8_t* ed25519_seed;   /* 32 bytes */
} quic_server_cert_material_t;

typedef struct {
    const uint8_t* server_priv_x25519;  /* 32 bytes */
    const uint8_t* server_random;       /* 32 bytes */
    quic_server_cert_material_t cert;
} quic_server_handshake_inputs_t;

/* Returns 0 on success, -1 on any failure (parse, unsupported offer,
 * crypto, build-overflow). On failure the conn is left in whatever
 * state earlier successful steps produced — callers should treat a
 * driver failure as fatal for the connection. */
int quic_server_drive_handshake(quic_conn_t* c,
                                const quic_server_handshake_inputs_t* in);

#endif
