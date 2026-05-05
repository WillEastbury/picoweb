/*
 * TLS certificate + private key loader.
 *
 * Sources, in priority order:
 *
 *   1. Env vars (k8s `valueFrom: secretKeyRef:` pattern)
 *      PICOWEB_TLS_CERT_PEM   — full chain PEM (multi-line, raw)
 *      PICOWEB_TLS_KEY_PEM    — private key PEM
 *
 *   2. Env paths (k8s `volumeMounts:` pattern, projected secret)
 *      PICOWEB_TLS_CERT_PATH  — filesystem path to chain PEM
 *      PICOWEB_TLS_KEY_PATH   — filesystem path to key PEM
 *
 *   3. Default disk layout
 *      _certs/<host>/server.crt + server.key   (per-SNI)
 *      _certs/server.crt        + server.key   (fallback / single-host)
 *
 * All loading happens at STARTUP. The handshake path NEVER touches
 * the filesystem — it looks up a normalized hostname in an in-memory
 * map (cert_store_lookup) and returns a pre-decoded DER cert chain
 * + private key.
 *
 * Memory model:
 *   - The cert_store owns its DER buffers. Caller passes in storage
 *     (typically the worker arena), the store carves it up at
 *     load time, and after that point everything is immutable.
 *   - There is exactly one cert_store, populated on the boot thread
 *     before workers spawn. Workers see it by const pointer.
 *
 * Key types recognised:
 *   - Ed25519 (PKCS#8, RFC 8410)             — preferred (small, fast)
 *   - ECDSA P-256 (SEC1 or PKCS#8)           — placeholder, not signed
 *   - RSA (PKCS#1 or PKCS#8)                 — placeholder, not signed
 *
 * The actual signing routines (CertificateVerify) are NOT in this
 * push — we just identify the key type so the handshake can pick
 * the right SignatureScheme later.
 */
#ifndef PICOWEB_USERSPACE_TLS_CERT_H
#define PICOWEB_USERSPACE_TLS_CERT_H

#include <stddef.h>
#include <stdint.h>

#define CERT_HOSTNAME_MAX 253u            /* RFC 1035 §2.3.4 */
#define CERT_STORE_MAX_HOSTS 32u          /* spike-grade cap */

typedef enum {
    CERT_KEY_UNKNOWN = 0,
    CERT_KEY_ED25519,
    CERT_KEY_ECDSA_P256,
    CERT_KEY_RSA,
} cert_key_type_t;

typedef struct {
    /* Lowercased ASCII hostname; "" for the default/fallback entry. */
    char hostname[CERT_HOSTNAME_MAX + 1];
    /* Cert chain as concatenated DER blobs (server cert first, then
     * intermediates). Pointer + length into the store's arena. */
    const uint8_t* chain_der;
    size_t chain_der_len;
    /* Per-cert lengths (for building the wire-format Certificate
     * message), in chain order. cert_count is the number of certs. */
    int    cert_count;
    size_t cert_lens[8];           /* hard cap; chains > 8 rejected */
    /* Private key in DER (PKCS#8 or SEC1 form depending on key_type). */
    const uint8_t* key_der;
    size_t key_der_len;
    cert_key_type_t key_type;
} cert_entry_t;

typedef struct {
    cert_entry_t entries[CERT_STORE_MAX_HOSTS];
    int          n_entries;
    /* Index of the default/fallback entry, or -1 if none. */
    int          default_idx;
    /* Backing arena (caller-owned). All chain_der/key_der pointers
     * live inside [arena, arena+arena_cap). */
    uint8_t*     arena;
    size_t       arena_cap;
    size_t       arena_used;
} cert_store_t;

/* Initialise an empty cert store backed by `arena_storage` (at least
 * `arena_cap` bytes). Returns 0 on success. */
int cert_store_init(cert_store_t* s, void* arena_storage, size_t arena_cap);

/* Load all certs visible at startup:
 *   - env (PICOWEB_TLS_CERT_PEM/KEY_PEM)
 *   - env paths (PICOWEB_TLS_CERT_PATH/KEY_PATH)
 *   - certs_dir (e.g. "_certs"), scanning for <host>/ subdirs and
 *     a fallback `server.crt`/`server.key` pair at the root.
 *
 * Returns the number of host entries loaded, or -1 on error.
 *
 * Hostname normalization: each entry is lowercased ASCII; non-ASCII
 * names should be punycoded by the operator before placing in the
 * folder name. */
int cert_store_load(cert_store_t* s, const char* certs_dir);

/* Look up a cert entry for `hostname`. Returns an exact match if
 * one exists, otherwise the default entry, otherwise NULL.
 * `hostname` must be lowercased ASCII (use cert_normalize_hostname).
 * This call DOES NOT touch the filesystem. */
const cert_entry_t* cert_store_lookup(const cert_store_t* s,
                                      const char* hostname,
                                      size_t hostname_len);

/* In-place lowercase ASCII normalisation. Returns 0 on success,
 * -1 if `hostname` contains anything other than [A-Za-z0-9.-_]
 * or exceeds CERT_HOSTNAME_MAX. */
int cert_normalize_hostname(char* hostname, size_t* hostname_len);

/* Extract the 32-byte raw Ed25519 seed from a cert entry's PKCS#8
 * private key (RFC 8410 §7).
 *
 * Returns 0 on success, -1 if the entry is not Ed25519, the PKCS#8
 * structure is malformed, or `out_seed` is NULL. The seed is the
 * input to ed25519_pubkey_from_seed / ed25519_sign.
 *
 * Canonical Ed25519 PKCS#8 v1 layout (48 bytes):
 *   30 2e 02 01 00                  SEQUENCE / version 0
 *   30 05 06 03 2b 65 70            algorithm OID 1.3.101.112
 *   04 22 04 20 [seed:32]           OCTET STRING wrapping CurvePrivateKey
 *
 * v2 (with optional attributes / public key) is also accepted as
 * long as the algorithm OID is Ed25519 and the privateKey field
 * is the standard inner-OCTET-STRING wrapper. */
int cert_extract_ed25519_seed(const cert_entry_t* e, uint8_t out_seed[32]);

#endif
