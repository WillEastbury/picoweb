/*
 * TLS 1.3 handshake message parsing + building (RFC 8446 §4).
 *
 * Spike scope:
 *   - Parse ClientHello: extract random, cipher_suites scan,
 *     extensions: server_name (RFC 6066), supported_groups,
 *     key_share (X25519), supported_versions (must offer 0x0304).
 *
 *   - Build ServerHello: random, fixed cipher_suite=TLS_CHACHA20_
 *     POLY1305_SHA256 (0x1303), extensions: supported_versions=
 *     0x0304, key_share (our X25519 pubkey echo).
 *
 *   - Compute the TLS 1.3 handshake-secrets layer: derive
 *     handshake_secret from (early_secret, ECDHE_shared, transcript)
 *     and from there the per-direction handshake traffic secrets.
 *
 * NOT in scope here (deferred): EncryptedExtensions, Certificate,
 * CertificateVerify (needs Ed25519/ECDSA signing), Finished, post-
 * handshake key updates. The parser/builder are sufficient to bring
 * the skeleton up to the point where openssl s_client could be
 * pointed at it and observe a valid ServerHello reply.
 *
 * Memory model:
 *   - Parser writes into a caller-provided `tls13_client_hello_t`.
 *     No allocations. SNI hostname is copied into a fixed buffer.
 *   - Builder writes wire bytes into a caller-provided buffer with
 *     bounds checking; returns the written length or -1 on overflow.
 */
#ifndef PICOWEB_USERSPACE_TLS_HANDSHAKE_H
#define PICOWEB_USERSPACE_TLS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/sha256.h"

#define TLS13_RANDOM_LEN          32u
#define TLS13_CHACHA20_POLY1305_SHA256  0x1303u
#define TLS13_SUPPORTED_VERSION   0x0304u
#define TLS13_NAMED_GROUP_X25519  0x001du

/* Maximum hostname extracted from SNI; oversized SNI rejected. */
#define TLS13_MAX_SNI_LEN  253u

/* Parsed ClientHello — only fields we actually need to make decisions. */
typedef struct {
    uint8_t  random[TLS13_RANDOM_LEN];

    /* Whether the client offered TLS_CHACHA20_POLY1305_SHA256. */
    int      offers_chacha_poly;

    /* Whether the client advertised supported_versions=TLS 1.3. */
    int      offers_tls13;

    /* Whether the client offered the X25519 named group AND a
     * key_share for it. If yes, ecdhe_pubkey is populated. */
    int      offers_x25519;
    uint8_t  ecdhe_pubkey[32];

    /* Whether the client advertised ed25519 (0x0807) in
     * signature_algorithms (and, if present, in
     * signature_algorithms_cert). RFC 8446 §4.2.3 / §4.2.3a.
     * If signature_algorithms_cert is absent (the common case),
     * signature_algorithms is used for both signing and cert
     * selection — that is the test we apply here. */
    int      offers_ed25519;

    /* legacy_session_id<0..32>. RFC 8446 §4.1.2. The server MUST
     * echo this back in ServerHello (compat-mode interop with TLS
     * 1.2 clients / browsers). */
    uint8_t  legacy_session_id[32];
    uint8_t  legacy_session_id_len;

    /* Server name (lowercased, ASCII; empty if no SNI). */
    char     sni[TLS13_MAX_SNI_LEN + 1];
    size_t   sni_len;

    /* Pointer to the original ClientHello bytes (handshake-msg
     * including the 4-byte handshake header). Used to feed the
     * transcript hash. */
    const uint8_t* raw;
    size_t         raw_len;

    /* ---- pre_shared_key (RFC 8446 §4.2.11) — captured but not
     * verified by the parser. The engine performs binder verification
     * after a ticket lookup. ----
     *
     * `psk_present` is 1 iff the extension was present and parsed
     * cleanly (well-formed lengths, at least one identity, matching
     * binder count). `psk_offer_count` is the number of (identity,
     * binder) pairs the client offered. The parser captures up to
     * TLS13_PSK_MAX_OFFERS pairs; extras are silently ignored.
     *
     * For each captured offer:
     *   psk_id_off[i]/psk_id_len[i]: byte range in `raw` of the
     *     identity opaque (the "ticket" the client returns)
     *   psk_obfuscated_age[i]: the 32-bit obfuscated_ticket_age
     *   psk_binder_off[i]/psk_binder_len[i]: byte range in `raw`
     *     of the binder HMAC value
     *
     * `psk_partial_ch_off` is the offset within `raw` at which the
     * truncated ClientHello ends — i.e., the first byte of the
     * binders<> length-prefix. The transcript hash for binder
     * verification is computed over raw[0..psk_partial_ch_off).
     *
     * Per RFC 8446 §4.2.11 pre_shared_key MUST be the LAST
     * extension in the CH; the parser enforces this. */
    int            psk_present;
    unsigned       psk_offer_count;
    size_t         psk_partial_ch_off;
    /* psk_key_exchange_modes (RFC 8446 §4.2.9) — required when
     * pre_shared_key is offered. We only support psk_dhe_ke (1). */
    int            psk_dhe_ke_offered;
    /* early_data extension (RFC 8446 §4.2.10) appearance in CH —
     * presence indicates the client wants 0-RTT under the FIRST
     * offered ticket. */
    int            offers_early_data;

#define TLS13_PSK_MAX_OFFERS 4
    size_t   psk_id_off       [TLS13_PSK_MAX_OFFERS];
    size_t   psk_id_len       [TLS13_PSK_MAX_OFFERS];
    uint32_t psk_obfuscated_age[TLS13_PSK_MAX_OFFERS];
    size_t   psk_binder_off   [TLS13_PSK_MAX_OFFERS];
    size_t   psk_binder_len   [TLS13_PSK_MAX_OFFERS];
} tls13_client_hello_t;

/* Parse a ClientHello from the wire. `msg` points at the first byte
 * of the handshake message header (0x01 client_hello, then 24-bit
 * length). `msg_len` is the total length of msg.
 *
 * Returns 0 on success, -1 on parse error or unsupported field. */
int tls13_parse_client_hello(const uint8_t* msg, size_t msg_len,
                             tls13_client_hello_t* out);

/* Build a ServerHello in `out[0..out_cap)`. The handshake header
 * (0x02 server_hello + 24-bit length) is included.
 *
 * Inputs:
 *   server_random[32]    — fresh server random
 *   our_pubkey[32]       — our X25519 ephemeral pubkey to echo back
 *   session_id           — bytes from the client's legacy_session_id
 *                          (echoed verbatim per RFC 8446 §4.1.3 / §D.4).
 *                          May be NULL iff session_id_len == 0.
 *   session_id_len       — length 0..32 of session_id
 *
 * Returns the number of bytes written, or -1 on overflow. */
int tls13_build_server_hello(uint8_t* out, size_t out_cap,
                             const uint8_t server_random[TLS13_RANDOM_LEN],
                             const uint8_t our_pubkey[32],
                             const uint8_t* session_id,
                             uint8_t session_id_len);

/* PSK-aware variant. If `selected_psk_identity` >= 0, the SH includes
 * a pre_shared_key extension (RFC 8446 §4.2.11) advertising the
 * accepted identity index. Otherwise behaves identically to
 * tls13_build_server_hello. */
int tls13_build_server_hello_psk(uint8_t* out, size_t out_cap,
                                 const uint8_t server_random[TLS13_RANDOM_LEN],
                                 const uint8_t our_pubkey[32],
                                 const uint8_t* session_id,
                                 uint8_t session_id_len,
                                 int selected_psk_identity);

/* Build an EncryptedExtensions handshake message (RFC 8446 §4.3.1).
 *
 * Spike: emits an empty extensions list. (No ALPN, no SNI ack — both
 * legitimate for a minimal HTTP/1.1 server.) Includes the 4-byte
 * handshake header. Returns bytes written, or -1 on overflow. */
int tls13_build_encrypted_extensions(uint8_t* out, size_t out_cap);

/* EE variant. When include_early_data != 0, includes a single
 * early_data extension (RFC 8446 §4.2.10) with empty body — used to
 * signal 0-RTT acceptance to the client. */
int tls13_build_encrypted_extensions_ex(uint8_t* out, size_t out_cap,
                                        int include_early_data);

/* Build a Certificate handshake message (RFC 8446 §4.4.2).
 *
 *   struct {
 *     opaque certificate_request_context<0..255>;       // empty for server
 *     CertificateEntry certificate_list<0..2^24-1>;
 *   }
 *
 *   struct {
 *     opaque cert_data<1..2^24-1>;     // DER X.509
 *     Extension extensions<0..2^16-1>; // empty in spike
 *   } CertificateEntry;
 *
 * `chain_der` points at concatenated DER X.509 certs as produced by
 * the cert store; `cert_lens[0..n_certs-1]` give the per-cert byte
 * lengths. Includes the handshake header (0x0b + 24-bit len). */
int tls13_build_certificate(uint8_t* out, size_t out_cap,
                            const uint8_t* chain_der,
                            const size_t* cert_lens,
                            unsigned n_certs);

/* Build a Finished handshake message (RFC 8446 §4.4.4).
 *
 * `verify_data` is the 32-byte HMAC computed by tls13_compute_finished
 * (or by the caller via tls13_verify_finished's expected calc).
 * Includes handshake header (0x14 + 24-bit length). */
int tls13_build_finished(uint8_t* out, size_t out_cap,
                         const uint8_t verify_data[32]);

/* ---------------- NewSessionTicket (RFC 8446 §4.6.1) ---------------- */
/*
 * Builds a complete NewSessionTicket handshake message (incl. the
 * 0x04 + 24-bit length header) into `out`. Layout:
 *
 *   uint32 ticket_lifetime
 *   uint32 ticket_age_add
 *   opaque ticket_nonce<0..255>
 *   opaque ticket<1..2^16-1>      -- server-chosen opaque label
 *   Extension extensions<0..2^16-2>  -- emitted empty (no early_data)
 *
 * `ticket_id` is the opaque label the server will hand back to the
 * client; the server uses it to look up the per-ticket PSK in its
 * own store. Returns total bytes written, or -1 on error. */
int tls13_build_new_session_ticket(uint8_t* out, size_t out_cap,
                                   uint32_t lifetime_s,
                                   uint32_t age_add,
                                   const uint8_t* ticket_nonce,
                                   size_t nonce_len,
                                   const uint8_t* ticket_id,
                                   size_t id_len);

/* Per-ticket PSK derivation (RFC 8446 §4.6.1):
 *   PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
 *                           ticket_nonce, Hash.length)
 * Outputs 32 bytes. Returns 0 on success, -1 on bad inputs. */
int tls13_derive_resumption_psk(const uint8_t resumption_master_secret[32],
                                const uint8_t* ticket_nonce, size_t nonce_len,
                                uint8_t psk[32]);

/* ---------------- CertificateVerify (RFC 8446 §4.4.3) ---------------- */
/*
 * Per §4.4.3 the signed content is:
 *
 *   64 bytes of 0x20 (SP) padding
 * || ASCII context string (33 B for server, 33 B for client)
 * || 0x00 separator
 * || transcript hash (32 B for SHA-256-based suites)
 *
 * For ed25519 (SignatureScheme 0x0807), the whole 130-byte buffer is
 * fed into ed25519_sign as the message — Ed25519 hashes it itself.
 */

#define TLS13_SIG_SCHEME_ED25519 0x0807u

/* ASCII labels — 33 bytes each (no NUL). */
#define TLS13_CV_LABEL_SERVER "TLS 1.3, server CertificateVerify"
#define TLS13_CV_LABEL_CLIENT "TLS 1.3, client CertificateVerify"

#define TLS13_CV_SIGNED_LEN   130u   /* 64 + 33 + 1 + 32 */

/* Build the 130-byte CertificateVerify signed-data buffer.
 *
 *   is_server != 0  -> use the server context label
 *   is_server == 0  -> use the client context label (mTLS)
 *
 * Returns 0 on success, -1 on bad args. */
int tls13_build_certificate_verify_signed_data(uint8_t out[TLS13_CV_SIGNED_LEN],
                                               const uint8_t transcript_hash[32],
                                               int is_server);

/* Build a server CertificateVerify handshake message (RFC 8446 §4.4.3)
 * using Ed25519.
 *
 * Wire format (post handshake header):
 *   u16 SignatureScheme  = 0x0807 (ed25519)
 *   u16 sig_len          = 0x0040 (= 64)
 *   u8  signature[64]
 *
 * Includes the 4-byte handshake header (0x0f + 24-bit length).
 *
 * Inputs:
 *   transcript_hash[32]  — SHA-256 of all handshake messages so far
 *                          (CH .. ServerHello .. EE .. Certificate),
 *                          NOT including this CV.
 *   seed[32]             — Ed25519 raw seed (use cert_extract_ed25519_seed).
 *
 * The corresponding public key is derived internally from seed
 * (~50us extra; fine for one-per-handshake usage).
 *
 * Returns bytes written (= 4 + 4 + 64 = 72), or -1 on overflow / bad args. */
int tls13_build_certificate_verify(uint8_t* out, size_t out_cap,
                                   const uint8_t transcript_hash[32],
                                   const uint8_t seed[32]);

/* Compute the TLS 1.3 handshake-phase secrets per RFC 8446 §7.1.
 *
 * Inputs:
 *   ecdhe_shared[32]     — output of X25519(our_priv, peer_pub)
 *   transcript_hash[32]  — SHA-256 of (ClientHello || ServerHello),
 *                          AS THEY APPEAR ON THE WIRE (handshake
 *                          headers included).
 *
 * Outputs (all 32 bytes):
 *   handshake_secret               — RFC 8446 §7.1
 *   client_handshake_traffic_secret
 *   server_handshake_traffic_secret
 *
 * Returns 0 on success, -1 on internal error. */
int tls13_compute_handshake_secrets(const uint8_t ecdhe_shared[32],
                                    const uint8_t transcript_hash[32],
                                    uint8_t handshake_secret[32],
                                    uint8_t client_hs_traffic_secret[32],
                                    uint8_t server_hs_traffic_secret[32]);

/* Compute the TLS 1.3 application-phase secrets per RFC 8446 §7.1.
 *
 *   derived       = Derive-Secret(handshake_secret, "derived", "")
 *   master_secret = HKDF-Extract(salt=derived, IKM=00..00)
 *   c_ap_traffic  = Derive-Secret(master_secret, "c ap traffic",
 *                                 H(ClientHello..ServerFinished))
 *   s_ap_traffic  = Derive-Secret(master_secret, "s ap traffic",
 *                                 H(ClientHello..ServerFinished))
 *
 * `transcript_hash_through_server_finished` is the SHA-256 of the
 * full handshake-message stream up to AND including the server's
 * Finished message. (NOT including the client Finished — that
 * appears later and is verified against the SAME transcript hash.)
 *
 * Returns 0 on success, -1 on internal error. All sensitive
 * intermediates are wiped before return. */
int tls13_compute_application_secrets(const uint8_t handshake_secret[32],
                                      const uint8_t transcript_hash_through_server_finished[32],
                                      uint8_t master_secret[32],
                                      uint8_t client_ap_traffic_secret[32],
                                      uint8_t server_ap_traffic_secret[32]);

/* RFC 8446 §7.1 resumption_master_secret derivation:
 *
 *   resumption_master_secret =
 *     Derive-Secret(master_secret, "res master",
 *                   H(ClientHello..client_Finished))
 *
 * `transcript_hash_through_client_finished` is the SHA-256 of the
 * full handshake-message stream INCLUDING the client Finished.
 * Output `resumption_master_secret` is 32 bytes. Returns 0 on success.
 * The caller is responsible for wiping `master_secret` once no longer
 * needed (typically immediately after this call). */
int tls13_compute_resumption_master_secret(
    const uint8_t master_secret[32],
    const uint8_t transcript_hash_through_client_finished[32],
    uint8_t       resumption_master_secret[32]);

/* ---------------- Early-secret schedule (RFC 8446 §7.1) ---------------- */

/* early_secret = HKDF-Extract(salt=00..00, IKM = psk or 00..00).
 * Pass psk=NULL or psk_len=0 to get the "no-PSK" early secret used
 * by full handshakes. Output is 32 bytes. */
int tls13_compute_early_secret(const uint8_t* psk, size_t psk_len,
                               uint8_t early_secret[32]);

/* binder_key = Derive-Secret(early_secret,
 *                            is_external ? "ext binder" : "res binder",
 *                            "")
 * Used to verify PSK binders in CH (RFC 8446 §4.2.11.2).
 * is_external should be 0 for resumption PSKs (NewSessionTicket),
 * 1 for externally-provisioned PSKs. */
int tls13_compute_binder_key(const uint8_t early_secret[32],
                             int is_external,
                             uint8_t binder_key[32]);

/* Compute the 32-byte PSK binder over `partial_ch_hash`, which is
 * SHA-256 of the ClientHello bytes from the start of the handshake
 * message up to (but not including) the binders length-prefix.
 * Returns 0 on success. Equivalent to a Finished computation under
 * binder_key. */
int tls13_compute_psk_binder(const uint8_t binder_key[32],
                             const uint8_t partial_ch_hash[32],
                             uint8_t binder_out[32]);

/* client_early_traffic_secret = Derive-Secret(early_secret,
 *                                  "c e traffic", H(CH))
 * Used to install 0-RTT decryption keys on the server BEFORE the
 * handshake-traffic keys come online. */
int tls13_compute_client_early_traffic_secret(
    const uint8_t early_secret[32],
    const uint8_t transcript_hash_through_client_hello[32],
    uint8_t       client_early_traffic_secret[32]);

/* PSK-aware variant of tls13_compute_handshake_secrets. The early
 * secret is extracted from the supplied PSK rather than from the
 * all-zero IKM. Pass psk=NULL or psk_len=0 to fall back to the
 * full-handshake derivation. */
int tls13_compute_handshake_secrets_psk(const uint8_t* psk, size_t psk_len,
                                        const uint8_t ecdhe_shared[32],
                                        const uint8_t transcript_hash[32],
                                        uint8_t handshake_secret[32],
                                        uint8_t client_hs_traffic_secret[32],
                                        uint8_t server_hs_traffic_secret[32]);

/* ---------------- Handshake transcript hash ---------------- */
/*
 * Convenience wrapper around the SHA-256 streaming context for the
 * running TLS 1.3 transcript hash. Each handshake message is fed in
 * (including its 4-byte handshake header). Snapshot can be taken at
 * any point without consuming the context.
 *
 *   tls13_transcript_t t;
 *   tls13_transcript_init(&t);
 *   tls13_transcript_update(&t, ch_bytes, ch_len);
 *   tls13_transcript_update(&t, sh_bytes, sh_len);
 *   uint8_t h[32];
 *   tls13_transcript_snapshot(&t, h);   // hash for handshake secrets
 *   ... continue updating with EE / Cert / CV / Finished ...
 */
typedef struct {
    sha256_ctx sha;
} tls13_transcript_t;

void tls13_transcript_init(tls13_transcript_t* t);
void tls13_transcript_update(tls13_transcript_t* t,
                             const uint8_t* msg, size_t len);
void tls13_transcript_snapshot(const tls13_transcript_t* t, uint8_t out[32]);

#endif
