/*
 * TLS certificate + private key loader — implementation.
 *
 * Strict zero-allocation after startup: this whole file runs ONCE
 * during boot, populates a cert_store_t living in the worker arena,
 * and is never re-entered. The handshake path uses cert_store_lookup
 * which is a pure in-memory walk.
 */

#define _POSIX_C_SOURCE 200809L

#include "cert.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pem.h"

/* ----------------- arena helpers ----------------- */

static void* arena_alloc(cert_store_t* s, size_t n) {
    /* 16-byte align so DER blobs are convenient to mmap-equivalent. */
    size_t aligned = (s->arena_used + 15u) & ~(size_t)15u;
    if (aligned + n > s->arena_cap) return NULL;
    void* p = s->arena + aligned;
    s->arena_used = aligned + n;
    return p;
}

/* ----------------- file I/O (startup only) ----------------- */

/* Read entire file into a freshly arena-allocated buffer. Returns
 * NULL on error. Caller gets the buffer + length. */
static const char* slurp_file(cert_store_t* s, const char* path,
                              size_t* out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    if (st.st_size <= 0 || st.st_size > (1 << 20)) {  /* 1 MiB cap */
        close(fd); return NULL;
    }
    char* buf = (char*)arena_alloc(s, (size_t)st.st_size);
    if (!buf) { close(fd); return NULL; }
    size_t total = 0;
    while (total < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + total, (size_t)st.st_size - total);
        if (n <= 0) { close(fd); return NULL; }
        total += (size_t)n;
    }
    close(fd);
    *out_len = total;
    return buf;
}

/* ----------------- key type detection ----------------- */

/* Detect key type by sniffing PKCS#8 algorithm OID.
 *
 *   PKCS#8 PrivateKeyInfo:
 *     SEQUENCE {
 *       INTEGER 0,                    -- version
 *       SEQUENCE { OID algorithm, ... }, -- algorithm identifier
 *       OCTET STRING ...
 *     }
 *
 * We don't fully parse ASN.1 here; we just look for known OIDs as
 * byte strings inside the first ~32 bytes. Robust enough for the
 * handful of well-formed keys an operator puts in _certs/.
 *
 * OID byte sequences (with the 0x06 OID tag and 1-byte length prefix):
 *   Ed25519     : 06 03 2b 65 70                   (1.3.101.112)
 *   id-ecPublicKey: 06 07 2a 86 48 ce 3d 02 01      (1.2.840.10045.2.1)
 *                   followed by P-256 OID 06 08 2a 86 48 ce 3d 03 01 07
 *   rsaEncryption: 06 09 2a 86 48 86 f7 0d 01 01 01 (1.2.840.113549.1.1.1)
 *
 * Also handles SEC1 ECDSA: starts with 30 .. 02 01 01 04 20 (priv key)
 *   and contains the P-256 named curve OID.
 */
static cert_key_type_t detect_key_type(const uint8_t* der, size_t der_len) {
    if (der_len < 8) return CERT_KEY_UNKNOWN;

    /* Search the first 64 bytes (OID lives inside the algorithm
     * identifier near the start) for known OID byte runs. */
    size_t scan = der_len < 64 ? der_len : 64;

    static const uint8_t ed25519_oid[]  = {0x06,0x03,0x2b,0x65,0x70};
    static const uint8_t ec_pub_oid[]   = {0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};
    static const uint8_t p256_oid[]     = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    static const uint8_t rsa_oid[]      = {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01};

#define HAS(oid) (scan >= sizeof(oid) && memmem(der, scan, oid, sizeof(oid)))
    if (HAS(ed25519_oid)) return CERT_KEY_ED25519;
    if (HAS(rsa_oid))     return CERT_KEY_RSA;
    if (HAS(ec_pub_oid) || HAS(p256_oid)) return CERT_KEY_ECDSA_P256;
#undef HAS
    return CERT_KEY_UNKNOWN;
}

/* ----------------- entry building ----------------- */

/* Add (or replace) an entry for `hostname` (use "" for default).
 * Decodes both PEMs into the arena. Returns 0 on success. */
static int add_entry(cert_store_t* s, const char* hostname,
                     const char* cert_pem, size_t cert_pem_len,
                     const char* key_pem,  size_t key_pem_len) {
    if (s->n_entries >= (int)CERT_STORE_MAX_HOSTS) return -1;

    /* Cert chain: try concatenated CERTIFICATE blocks. */
    /* Worst case: DER ~= 3/4 of PEM. Allocate the PEM length as cap. */
    uint8_t* chain = (uint8_t*)arena_alloc(s, cert_pem_len);
    if (!chain) return -1;
    int chain_count = 0;
    int chain_len = pem_decode_chain(cert_pem, cert_pem_len, "CERTIFICATE",
                                     chain, cert_pem_len, &chain_count);
    if (chain_len < 0 || chain_count <= 0 || chain_count > 8) return -1;

    /* Compute per-cert lengths by re-running pem_decode_chain
     * conceptually — easier: we re-decode each and record sizes by
     * scanning. Simpler: just record the total in entry; per-cert
     * lengths require a tiny ASN.1 length walk over the DER blob. */
    size_t cert_lens[8] = {0};
    {
        size_t off = 0;
        for (int i = 0; i < chain_count; i++) {
            if (off + 2 > (size_t)chain_len) return -1;
            /* DER cert is SEQUENCE: 0x30 then length bytes (DER
             * length encoding). We don't enforce 0x30 — many CAs
             * use it but RFC 5280 also permits explicit. */
            if (chain[off] != 0x30) return -1;
            size_t l;
            uint8_t b1 = chain[off + 1];
            size_t header_len;
            if (b1 < 0x80) { l = b1; header_len = 2; }
            else {
                uint8_t nb = b1 & 0x7F;
                if (nb == 0 || nb > 4) return -1;
                if (off + 2 + nb > (size_t)chain_len) return -1;
                l = 0;
                for (uint8_t j = 0; j < nb; j++) l = (l << 8) | chain[off + 2 + j];
                header_len = 2 + nb;
            }
            /* Bound the cert length to a sane ceiling. A real cert
             * is at most a few KB; multi-MB values can only be
             * malformed or hostile. Also avoids any chance of
             * header_len + l wrapping size_t on 32-bit builds. */
            if (l > (1u << 20)) return -1;
            cert_lens[i] = header_len + l;
            if (off + cert_lens[i] > (size_t)chain_len) return -1;
            off += cert_lens[i];
        }
        if (off != (size_t)chain_len) return -1;
    }

    /* Private key: try several PEM labels in priority order. */
    static const char* key_labels[] = {
        "PRIVATE KEY",          /* PKCS#8 — generic */
        "EC PRIVATE KEY",       /* SEC1 */
        "RSA PRIVATE KEY",      /* PKCS#1 */
        NULL
    };
    uint8_t* key = (uint8_t*)arena_alloc(s, key_pem_len);
    if (!key) return -1;
    int key_len = -1;
    for (int i = 0; key_labels[i]; i++) {
        key_len = pem_decode(key_pem, key_pem_len, key_labels[i],
                             key, key_pem_len);
        if (key_len > 0) break;
    }
    if (key_len <= 0) return -1;

    cert_entry_t* e = &s->entries[s->n_entries];
    memset(e, 0, sizeof(*e));
    size_t hl = strlen(hostname);
    if (hl > CERT_HOSTNAME_MAX) return -1;
    memcpy(e->hostname, hostname, hl);
    e->hostname[hl] = 0;
    e->chain_der = chain;
    e->chain_der_len = (size_t)chain_len;
    e->cert_count = chain_count;
    for (int i = 0; i < chain_count; i++) e->cert_lens[i] = cert_lens[i];
    e->key_der = key;
    e->key_der_len = (size_t)key_len;
    e->key_type = detect_key_type(key, (size_t)key_len);

    if (hl == 0) s->default_idx = s->n_entries;
    s->n_entries++;
    return 0;
}

/* ----------------- public API ----------------- */

int cert_store_init(cert_store_t* s, void* arena_storage, size_t arena_cap) {
    if (!s || !arena_storage || arena_cap < 4096) return -1;
    memset(s, 0, sizeof(*s));
    s->arena = (uint8_t*)arena_storage;
    s->arena_cap = arena_cap;
    s->arena_used = 0;
    s->default_idx = -1;
    return 0;
}

int cert_normalize_hostname(char* hostname, size_t* hostname_len) {
    if (!hostname || !hostname_len) return -1;
    size_t n = *hostname_len;
    if (n == 0 || n > CERT_HOSTNAME_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)hostname[i];
        /* Strict label charset: letters, digits, dot, hyphen, underscore. */
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) {
            return -1;
        }
        if (c >= 'A' && c <= 'Z') hostname[i] = (char)(c - 'A' + 'a');
    }
    return 0;
}

/* ---------------- Ed25519 seed extraction (RFC 8410 §7) ---------------- */
/*
 * Tiny DER walker. We only handle short-form lengths (high bit clear)
 * because Ed25519 PKCS#8 is always under 127 bytes — the algorithm
 * SEQUENCE is 5 bytes, the OCTET STRING wrappers are 32-34 bytes, and
 * the whole thing is 48 bytes for v1 and a few dozen more for v2.
 *
 * Returns 0 and advances *off on success; -1 on malformed/long-form.
 */
static int der_read_tag_len(const uint8_t* der, size_t der_len,
                            size_t* off,
                            uint8_t* out_tag, size_t* out_len) {
    if (*off + 2 > der_len) return -1;
    uint8_t tag = der[*off];
    uint8_t l   = der[*off + 1];
    if (l & 0x80) return -1;            /* long-form length: not supported */
    if (*off + 2 + l > der_len) return -1;
    *out_tag = tag;
    *out_len = l;
    *off += 2;
    return 0;
}

int cert_extract_ed25519_seed(const cert_entry_t* e, uint8_t out_seed[32]) {
    if (!e || !out_seed) return -1;
    if (e->key_type != CERT_KEY_ED25519) return -1;
    if (!e->key_der || e->key_der_len < 16) return -1;

    const uint8_t* d = e->key_der;
    size_t        n  = e->key_der_len;
    size_t        o  = 0;
    uint8_t       tag;
    size_t        len;

    /* PrivateKeyInfo SEQUENCE. */
    if (der_read_tag_len(d, n, &o, &tag, &len) < 0) return -1;
    if (tag != 0x30) return -1;
    size_t end_outer = o + len;
    if (end_outer > n) return -1;

    /* version INTEGER. Per RFC 5958 v1=0, v2=1. Either is fine. */
    if (der_read_tag_len(d, n, &o, &tag, &len) < 0) return -1;
    if (tag != 0x02 || len != 1) return -1;
    o += len;

    /* algorithm AlgorithmIdentifier SEQUENCE. */
    if (der_read_tag_len(d, n, &o, &tag, &len) < 0) return -1;
    if (tag != 0x30) return -1;
    /* Inside: must contain the Ed25519 OID 1.3.101.112 (06 03 2b 65 70).
     * detect_key_type already verified Ed25519 at the top, but we
     * sanity-check here too to defend against a key_type lie. */
    static const uint8_t ed25519_oid[] = {0x06,0x03,0x2b,0x65,0x70};
    if (len < sizeof(ed25519_oid)) return -1;
    if (memcmp(d + o, ed25519_oid, sizeof(ed25519_oid)) != 0) return -1;
    o += len;

    /* privateKey OCTET STRING wrapping CurvePrivateKey. */
    if (der_read_tag_len(d, n, &o, &tag, &len) < 0) return -1;
    if (tag != 0x04) return -1;
    /* Outer OCTET STRING content must itself be an OCTET STRING of
     * exactly 32 bytes (the raw Ed25519 seed). */
    if (len < 2 + 32) return -1;
    if (d[o] != 0x04 || d[o + 1] != 0x20) return -1;
    if (o + 2 + 32 > n) return -1;

    memcpy(out_seed, d + o + 2, 32);
    return 0;
}

const cert_entry_t* cert_store_lookup(const cert_store_t* s,
                                      const char* hostname,
                                      size_t hostname_len) {
    if (!s) return NULL;
    if (hostname && hostname_len > 0 && hostname_len <= CERT_HOSTNAME_MAX) {
        for (int i = 0; i < s->n_entries; i++) {
            const cert_entry_t* e = &s->entries[i];
            size_t el = strlen(e->hostname);
            if (el == hostname_len && memcmp(e->hostname, hostname, el) == 0) {
                return e;
            }
        }
    }
    if (s->default_idx >= 0) return &s->entries[s->default_idx];
    return NULL;
}

/* Walk certs_dir and load every <host>/ subfolder. Returns count of
 * host entries added. */
static int load_disk_dir(cert_store_t* s, const char* certs_dir) {
    int added = 0;

    /* Fallback root: certs_dir/server.crt + server.key  -> "" entry. */
    {
        char crt_path[1024], key_path[1024];
        snprintf(crt_path, sizeof(crt_path), "%s/server.crt", certs_dir);
        snprintf(key_path, sizeof(key_path), "%s/server.key", certs_dir);
        size_t cl, kl;
        const char* cp = slurp_file(s, crt_path, &cl);
        const char* kp = slurp_file(s, key_path, &kl);
        if (cp && kp) {
            if (add_entry(s, "", cp, cl, kp, kl) == 0) added++;
        }
    }

    /* Per-host subfolders. */
    DIR* d = opendir(certs_dir);
    if (!d) return added;
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;        /* skip ".", "..", hidden */

        /* Build subdir path; check it's a directory. */
        char sub[1024], crt_path[1280], key_path[1280];
        snprintf(sub, sizeof(sub), "%s/%s", certs_dir, de->d_name);
        struct stat st;
        if (stat(sub, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        /* Validate hostname charset. */
        char host[CERT_HOSTNAME_MAX + 1];
        size_t hl = strlen(de->d_name);
        if (hl == 0 || hl > CERT_HOSTNAME_MAX) continue;
        memcpy(host, de->d_name, hl);
        host[hl] = 0;
        if (cert_normalize_hostname(host, &hl) != 0) continue;

        snprintf(crt_path, sizeof(crt_path), "%s/server.crt", sub);
        snprintf(key_path, sizeof(key_path), "%s/server.key", sub);
        size_t cl, kl;
        const char* cp = slurp_file(s, crt_path, &cl);
        const char* kp = slurp_file(s, key_path, &kl);
        if (!cp || !kp) continue;
        if (add_entry(s, host, cp, cl, kp, kl) == 0) added++;
    }
    closedir(d);
    return added;
}

/* Load from raw env PEM strings (the k8s `secretKeyRef` pattern). */
static int load_env_inline(cert_store_t* s) {
    const char* cert_pem = getenv("PICOWEB_TLS_CERT_PEM");
    const char* key_pem  = getenv("PICOWEB_TLS_KEY_PEM");
    if (!cert_pem || !key_pem) return 0;
    /* Treat env-mode as the default entry (no SNI in env). */
    int rc = add_entry(s, "", cert_pem, strlen(cert_pem),
                              key_pem,  strlen(key_pem));
    return rc == 0 ? 1 : 0;
}

/* Load from env-supplied filesystem paths (k8s `volumeMounts`). */
static int load_env_paths(cert_store_t* s) {
    const char* cert_path = getenv("PICOWEB_TLS_CERT_PATH");
    const char* key_path  = getenv("PICOWEB_TLS_KEY_PATH");
    if (!cert_path || !key_path) return 0;
    size_t cl, kl;
    const char* cp = slurp_file(s, cert_path, &cl);
    const char* kp = slurp_file(s, key_path, &kl);
    if (!cp || !kp) return 0;
    int rc = add_entry(s, "", cp, cl, kp, kl);
    return rc == 0 ? 1 : 0;
}

int cert_store_load(cert_store_t* s, const char* certs_dir) {
    if (!s) return -1;
    int added = 0;

    /* Order matters: env overrides disk. We load env first; if an
     * env-default is present, the disk loader's default would replace
     * it via default_idx unless we skip the disk fallback when an env
     * default exists. Easiest: load env first, and skip the disk
     * fallback root if default_idx >= 0 already. */
    added += load_env_inline(s);
    added += load_env_paths(s);

    if (certs_dir && *certs_dir) {
        /* Load per-host disk entries; the disk fallback may also
         * become the default if env hasn't already supplied one. */
        int default_was = s->default_idx;
        int disk_added = load_disk_dir(s, certs_dir);
        added += disk_added;
        /* If env had set a default, don't let the disk fallback
         * silently win: rewind default_idx. */
        if (default_was >= 0) s->default_idx = default_was;
    }

    return added > 0 ? added : -1;
}
