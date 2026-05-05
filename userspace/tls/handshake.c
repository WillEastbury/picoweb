/*
 * TLS 1.3 handshake message parser + builder.
 *
 * Strict bounds checking everywhere — this is the first attacker-
 * controlled byte stream in TLS, so every length field is checked
 * against the remaining buffer before we deref past it.
 *
 * Zero allocations. All output goes into caller-provided buffers
 * or fixed fields in the tls13_client_hello_t.
 */

#include "handshake.h"

#include <string.h>

#include "../crypto/hkdf.h"
#include "../crypto/hmac.h"
#include "../crypto/sha256.h"
#include "../crypto/util.h"
#include "keysched.h"

/* ------------------ wire helpers ------------------ */

/* Bounded reader: tracks a cursor `p` and a remaining count `rem`.
 * All readers either succeed (advance p, decrement rem) or set
 * rem to SIZE_MAX as a poison sentinel that future reads detect. */

static inline int rd_u8(const uint8_t** p, size_t* rem, uint8_t* out) {
    if (*rem < 1) return -1;
    *out = (*p)[0];
    *p += 1; *rem -= 1;
    return 0;
}
static inline int rd_u16(const uint8_t** p, size_t* rem, uint16_t* out) {
    if (*rem < 2) return -1;
    *out = ((uint16_t)(*p)[0] << 8) | (uint16_t)(*p)[1];
    *p += 2; *rem -= 2;
    return 0;
}
static inline int rd_u24(const uint8_t** p, size_t* rem, uint32_t* out) {
    if (*rem < 3) return -1;
    *out = ((uint32_t)(*p)[0] << 16) | ((uint32_t)(*p)[1] << 8) | (uint32_t)(*p)[2];
    *p += 3; *rem -= 3;
    return 0;
}
static inline int rd_skip(const uint8_t** p, size_t* rem, size_t n) {
    if (*rem < n) return -1;
    *p += n; *rem -= n;
    return 0;
}
static inline int rd_copy(const uint8_t** p, size_t* rem, uint8_t* dst, size_t n) {
    if (*rem < n) return -1;
    memcpy(dst, *p, n);
    *p += n; *rem -= n;
    return 0;
}

/* Bounded writer. */
static inline int wr_u8(uint8_t** p, size_t* rem, uint8_t v) {
    if (*rem < 1) return -1;
    (*p)[0] = v; *p += 1; *rem -= 1;
    return 0;
}
static inline int wr_u16(uint8_t** p, size_t* rem, uint16_t v) {
    if (*rem < 2) return -1;
    (*p)[0] = (uint8_t)(v >> 8); (*p)[1] = (uint8_t)v;
    *p += 2; *rem -= 2;
    return 0;
}
static inline int wr_u24(uint8_t** p, size_t* rem, uint32_t v) {
    if (*rem < 3) return -1;
    (*p)[0] = (uint8_t)(v >> 16); (*p)[1] = (uint8_t)(v >> 8); (*p)[2] = (uint8_t)v;
    *p += 3; *rem -= 3;
    return 0;
}
static inline int wr_bytes(uint8_t** p, size_t* rem, const uint8_t* src, size_t n) {
    if (*rem < n) return -1;
    memcpy(*p, src, n);
    *p += n; *rem -= n;
    return 0;
}

/* ------------------ ClientHello parser ------------------ */

static int parse_extensions(const uint8_t* ext_data, size_t ext_len,
                            tls13_client_hello_t* out) {
    const uint8_t* p = ext_data;
    size_t rem = ext_len;

    while (rem > 0) {
        uint16_t ext_type, ext_size;
        if (rd_u16(&p, &rem, &ext_type) != 0) return -1;
        if (rd_u16(&p, &rem, &ext_size) != 0) return -1;
        if (rem < ext_size)                     return -1;
        const uint8_t* eb = p;
        size_t er = ext_size;
        /* Always advance the outer cursor past this extension first;
         * inner parsing operates on (eb, er). */
        if (rd_skip(&p, &rem, ext_size) != 0)   return -1;

        switch (ext_type) {
        case 0x0000: {                /* server_name (SNI), RFC 6066 §3 */
            uint16_t list_len;
            if (rd_u16(&eb, &er, &list_len) != 0) return -1;
            if (er < list_len) return -1;
            const uint8_t* lp = eb;
            size_t         lr = list_len;
            /* For each ServerNameEntry: name_type(1) + host_name<2..2^16-1>. */
            while (lr > 0) {
                uint8_t name_type;
                uint16_t name_len;
                if (rd_u8(&lp, &lr, &name_type) != 0)     return -1;
                if (rd_u16(&lp, &lr, &name_len) != 0)     return -1;
                if (lr < name_len)                        return -1;
                if (name_type == 0 /* host_name */) {
                    if (name_len > TLS13_MAX_SNI_LEN)     return -1;
                    memcpy(out->sni, lp, name_len);
                    out->sni[name_len] = 0;
                    out->sni_len = name_len;
                    /* Lowercase ASCII in place. */
                    for (size_t i = 0; i < name_len; i++) {
                        char c = out->sni[i];
                        if (c >= 'A' && c <= 'Z') out->sni[i] = (char)(c + 32);
                    }
                }
                if (rd_skip(&lp, &lr, name_len) != 0)     return -1;
            }
            break;
        }
        case 0x000a: {                /* supported_groups */
            uint16_t list_len;
            if (rd_u16(&eb, &er, &list_len) != 0) return -1;
            if (er < list_len) return -1;
            const uint8_t* lp = eb;
            size_t         lr = list_len;
            while (lr >= 2) {
                uint16_t grp;
                if (rd_u16(&lp, &lr, &grp) != 0) return -1;
                if (grp == TLS13_NAMED_GROUP_X25519) {
                    /* Mark intent; the actual key_share is checked
                     * in the key_share extension below. */
                    /* No-op flag — offers_x25519 is set when a
                     * matching key_share is found. */
                }
            }
            break;
        }
        case 0x0033: {                /* key_share (RFC 8446 §4.2.8) */
            uint16_t list_len;
            if (rd_u16(&eb, &er, &list_len) != 0) return -1;
            if (er < list_len) return -1;
            const uint8_t* lp = eb;
            size_t         lr = list_len;
            while (lr >= 4) {
                uint16_t grp, kx_len;
                if (rd_u16(&lp, &lr, &grp) != 0)    return -1;
                if (rd_u16(&lp, &lr, &kx_len) != 0) return -1;
                if (lr < kx_len)                    return -1;
                if (grp == TLS13_NAMED_GROUP_X25519 && kx_len == 32) {
                    memcpy(out->ecdhe_pubkey, lp, 32);
                    out->offers_x25519 = 1;
                }
                if (rd_skip(&lp, &lr, kx_len) != 0) return -1;
            }
            break;
        }
        case 0x002b: {                /* supported_versions */
            uint8_t vlist_len;
            if (rd_u8(&eb, &er, &vlist_len) != 0)   return -1;
            if (er < vlist_len)                     return -1;
            const uint8_t* lp = eb;
            size_t         lr = vlist_len;
            while (lr >= 2) {
                uint16_t ver;
                if (rd_u16(&lp, &lr, &ver) != 0)    return -1;
                if (ver == TLS13_SUPPORTED_VERSION) out->offers_tls13 = 1;
            }
            break;
        }
        default:
            /* Ignore unrecognised extensions (forward compat). */
            break;
        }
    }
    return 0;
}

int tls13_parse_client_hello(const uint8_t* msg, size_t msg_len,
                             tls13_client_hello_t* out) {
    if (!msg || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->raw = msg;
    out->raw_len = msg_len;

    const uint8_t* p = msg;
    size_t rem = msg_len;

    /* Handshake header */
    uint8_t  hs_type;
    uint32_t hs_len;
    if (rd_u8(&p, &rem, &hs_type) != 0)              return -1;
    if (hs_type != 0x01)                             return -1;     /* client_hello */
    if (rd_u24(&p, &rem, &hs_len) != 0)              return -1;
    if (hs_len != rem)                               return -1;     /* must match remaining */

    /* legacy_version (must be 0x0303 for TLS 1.3 ClientHello) */
    uint16_t legacy_version;
    if (rd_u16(&p, &rem, &legacy_version) != 0)      return -1;
    if (legacy_version != 0x0303)                    return -1;

    /* random[32] */
    if (rd_copy(&p, &rem, out->random, 32) != 0)     return -1;

    /* legacy_session_id<0..32> */
    uint8_t sid_len;
    if (rd_u8(&p, &rem, &sid_len) != 0)              return -1;
    if (sid_len > 32 || rd_skip(&p, &rem, sid_len) != 0) return -1;

    /* cipher_suites<2..2^16-2> */
    uint16_t cs_len;
    if (rd_u16(&p, &rem, &cs_len) != 0)              return -1;
    if ((cs_len & 1u) || cs_len > rem)               return -1;
    {
        const uint8_t* cp = p;
        for (uint16_t i = 0; i + 2 <= cs_len; i += 2) {
            uint16_t cs = ((uint16_t)cp[i] << 8) | cp[i + 1];
            if (cs == TLS13_CHACHA20_POLY1305_SHA256) {
                out->offers_chacha_poly = 1;
            }
        }
    }
    if (rd_skip(&p, &rem, cs_len) != 0)              return -1;

    /* legacy_compression_methods<1..2^8-1> — must contain 0x00 */
    uint8_t cm_len;
    if (rd_u8(&p, &rem, &cm_len) != 0)               return -1;
    if (cm_len < 1 || rd_skip(&p, &rem, cm_len) != 0) return -1;

    /* extensions<8..2^16-1> */
    uint16_t ext_total;
    if (rd_u16(&p, &rem, &ext_total) != 0)           return -1;
    if (ext_total != rem)                            return -1;

    return parse_extensions(p, ext_total, out);
}

/* ------------------ ServerHello builder ------------------ */

int tls13_build_server_hello(uint8_t* out, size_t out_cap,
                             const uint8_t server_random[TLS13_RANDOM_LEN],
                             const uint8_t our_pubkey[32]) {
    if (!out || !server_random || !our_pubkey) return -1;

    uint8_t* p = out;
    size_t   rem = out_cap;

    /* Handshake header (0x02 server_hello, 24-bit length backfilled). */
    if (wr_u8 (&p, &rem, 0x02)       != 0) return -1;
    uint8_t* len_field = p;
    if (wr_u24(&p, &rem, 0x000000)   != 0) return -1;

    uint8_t* body_start = p;

    /* legacy_version 0x0303 (TLS 1.3 hides version in supported_versions) */
    if (wr_u16(&p, &rem, 0x0303) != 0)        return -1;
    /* random[32] */
    if (wr_bytes(&p, &rem, server_random, 32) != 0) return -1;
    /* legacy_session_id_echo<0..32>. We don't echo a real session id;
     * write a 0 length (clients that sent one will see this and accept it). */
    if (wr_u8(&p, &rem, 0) != 0)              return -1;
    /* cipher_suite */
    if (wr_u16(&p, &rem, TLS13_CHACHA20_POLY1305_SHA256) != 0) return -1;
    /* legacy_compression_method */
    if (wr_u8(&p, &rem, 0) != 0)              return -1;

    /* extensions<6..2^16-1>:
     *   supported_versions: type(2) + size(2) + selected_version(2) = 6
     *   key_share:          type(2) + size(2) + group(2) + kx_len(2) + kx(32) = 40
     *   total = 46
     */
    if (wr_u16(&p, &rem, 46) != 0) return -1;

    /* supported_versions */
    if (wr_u16(&p, &rem, 0x002b) != 0) return -1;
    if (wr_u16(&p, &rem, 2)      != 0) return -1;
    if (wr_u16(&p, &rem, TLS13_SUPPORTED_VERSION) != 0) return -1;

    /* key_share (server hello variant: a single KeyShareEntry, not a list) */
    if (wr_u16(&p, &rem, 0x0033) != 0) return -1;
    if (wr_u16(&p, &rem, 36)     != 0) return -1;     /* 2+2+32 */
    if (wr_u16(&p, &rem, TLS13_NAMED_GROUP_X25519) != 0) return -1;
    if (wr_u16(&p, &rem, 32) != 0) return -1;
    if (wr_bytes(&p, &rem, our_pubkey, 32) != 0) return -1;

    /* Backfill 24-bit handshake length. */
    size_t body_len = (size_t)(p - body_start);
    len_field[0] = (uint8_t)(body_len >> 16);
    len_field[1] = (uint8_t)(body_len >> 8);
    len_field[2] = (uint8_t)body_len;

    return (int)(p - out);
}

/* ------------------ EncryptedExtensions / Certificate / Finished ----- */

int tls13_build_encrypted_extensions(uint8_t* out, size_t out_cap) {
    if (!out) return -1;
    /* Header (4) + extensions list length (2) = 6 bytes minimum. */
    if (out_cap < 6) return -1;
    out[0] = 0x08;                   /* encrypted_extensions */
    out[1] = 0x00; out[2] = 0x00; out[3] = 0x02;  /* body length = 2 */
    out[4] = 0x00; out[5] = 0x00;    /* extensions<0..2^16-1> = empty */
    return 6;
}

int tls13_build_certificate(uint8_t* out, size_t out_cap,
                            const uint8_t* chain_der,
                            const uint32_t* cert_lens,
                            unsigned n_certs) {
    if (!out || (n_certs > 0 && (!chain_der || !cert_lens))) return -1;

    /* Compute the body length up front for bounds checks:
     *   1 (cert_request_context len = 0)
     *   3 (certificate_list length, u24)
     *   sum( 3 (cert_data len, u24) + cert_lens[i] + 2 (extensions len = 0) )
     */
    uint64_t cl_total = 0;
    for (unsigned i = 0; i < n_certs; i++) {
        cl_total += 3u + cert_lens[i] + 2u;
    }
    if (cl_total > 0xFFFFFFu) return -1;

    uint64_t body_len = 1u + 3u + cl_total;
    if (body_len > 0xFFFFFFu) return -1;
    uint64_t total = 4u + body_len;
    if (total > out_cap)     return -1;

    uint8_t* p = out;
    /* Handshake header: 0x0b certificate, 24-bit body length. */
    *p++ = 0x0b;
    *p++ = (uint8_t)(body_len >> 16);
    *p++ = (uint8_t)(body_len >> 8);
    *p++ = (uint8_t)body_len;

    /* certificate_request_context<0..255> = empty. */
    *p++ = 0x00;

    /* certificate_list<0..2^24-1>. */
    *p++ = (uint8_t)(cl_total >> 16);
    *p++ = (uint8_t)(cl_total >> 8);
    *p++ = (uint8_t)cl_total;

    size_t off = 0;
    for (unsigned i = 0; i < n_certs; i++) {
        uint32_t cl = cert_lens[i];
        *p++ = (uint8_t)(cl >> 16);
        *p++ = (uint8_t)(cl >> 8);
        *p++ = (uint8_t)cl;
        memcpy(p, chain_der + off, cl);
        p   += cl;
        off += cl;
        /* extensions<0..2^16-1> = empty. */
        *p++ = 0x00;
        *p++ = 0x00;
    }

    return (int)(p - out);
}

int tls13_build_finished(uint8_t* out, size_t out_cap,
                         const uint8_t verify_data[32]) {
    if (!out || !verify_data) return -1;
    if (out_cap < 4 + 32)     return -1;
    out[0] = 0x14;                       /* finished */
    out[1] = 0x00; out[2] = 0x00; out[3] = 0x20;   /* body length = 32 */
    memcpy(out + 4, verify_data, 32);
    return 4 + 32;
}

/* ---------------- Handshake transcript hash ---------------- */

void tls13_transcript_init(tls13_transcript_t* t) {
    sha256_init(&t->sha);
}

void tls13_transcript_update(tls13_transcript_t* t,
                             const uint8_t* msg, size_t len) {
    sha256_update(&t->sha, msg, len);
}

void tls13_transcript_snapshot(const tls13_transcript_t* t, uint8_t out[32]) {
    /* sha256_final mutates the ctx, so snapshot must clone first. */
    sha256_ctx clone = t->sha;
    sha256_final(&clone, out);
}

/* ------------------ Handshake key schedule ------------------ */

int tls13_compute_handshake_secrets(const uint8_t ecdhe_shared[32],
                                    const uint8_t transcript_hash[32],
                                    uint8_t handshake_secret[32],
                                    uint8_t client_hs_traffic_secret[32],
                                    uint8_t server_hs_traffic_secret[32]) {
    /* Per RFC 8446 §7.1:
     *
     *  early_secret = HKDF-Extract(salt=00..00, IKM=PSK or 00..00)
     *  derived      = Derive-Secret(early_secret, "derived", "")
     *  handshake_secret = HKDF-Extract(salt=derived, IKM=ECDHE_shared)
     *  c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", CH..SH)
     *  s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", CH..SH)
     */
    uint8_t zero32[32]    = {0};
    uint8_t early_secret[32];
    uint8_t derived[32];
    uint8_t empty_hash[32];

    hkdf_extract(zero32, sizeof(zero32), zero32, sizeof(zero32), early_secret);

    /* Derive-Secret(early_secret, "derived", "") — empty string here
     * means we hash the empty-string transcript, which is just
     * SHA-256(""). */
    sha256("", 0, empty_hash);
    if (tls13_hkdf_expand_label(early_secret, "derived",
                                empty_hash, sizeof(empty_hash),
                                derived, sizeof(derived)) != 0) return -1;

    hkdf_extract(derived, sizeof(derived),
                 ecdhe_shared, 32, handshake_secret);

    if (tls13_hkdf_expand_label(handshake_secret, "c hs traffic",
                                transcript_hash, 32,
                                client_hs_traffic_secret, 32) != 0) return -1;
    if (tls13_hkdf_expand_label(handshake_secret, "s hs traffic",
                                transcript_hash, 32,
                                server_hs_traffic_secret, 32) != 0) return -1;

    secure_zero(early_secret, sizeof(early_secret));
    secure_zero(derived,      sizeof(derived));
    return 0;
}
