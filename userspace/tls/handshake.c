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

#include "../crypto/ed25519.h"
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

static int parse_psk_extension(const uint8_t* eb_start, size_t er_total,
                               const uint8_t* raw_base, size_t raw_total,
                               tls13_client_hello_t* out) {
    /* RFC 8446 §4.2.11 OfferedPsks layout:
     *   PskIdentity identities<7..2^16-1>      // u16 length, then list
     *     each: opaque identity<1..2^16-1>     // u16 + bytes
     *           uint32 obfuscated_ticket_age
     *   PskBinderEntry binders<33..2^16-1>     // u16 length, then list
     *     each: opaque<32..255>                // u8 + bytes
     */
    const uint8_t* p = eb_start;
    size_t rem = er_total;

    uint16_t ids_total;
    if (rd_u16(&p, &rem, &ids_total) != 0) return -1;
    if (ids_total < 7 || rem < ids_total) return -1;

    /* Consume identities into out->psk_id_off/_len + obfuscated age. */
    {
        const uint8_t* lp = p;
        size_t         lr = ids_total;
        unsigned       n  = 0;
        while (lr > 0) {
            uint16_t id_len;
            if (rd_u16(&lp, &lr, &id_len) != 0) return -1;
            if (id_len < 1 || lr < id_len)      return -1;
            size_t id_off_in_raw = (size_t)((lp) - raw_base);
            if (id_off_in_raw > raw_total)      return -1;
            const uint8_t* id_start = lp;
            (void)id_start;
            if (rd_skip(&lp, &lr, id_len) != 0) return -1;
            uint32_t age;
            uint16_t hi, lo;
            if (rd_u16(&lp, &lr, &hi) != 0)     return -1;
            if (rd_u16(&lp, &lr, &lo) != 0)     return -1;
            age = ((uint32_t)hi << 16) | lo;
            if (n < TLS13_PSK_MAX_OFFERS) {
                out->psk_id_off[n]        = id_off_in_raw;
                out->psk_id_len[n]        = id_len;
                out->psk_obfuscated_age[n] = age;
            }
            n++;
        }
        out->psk_offer_count = n;
        if (n == 0) return -1;
    }
    /* Skip past identities to binders. */
    if (rd_skip(&p, &rem, ids_total) != 0)        return -1;

    /* The OFFSET (within raw_base) of the start of the binders
     * length-prefix is the truncation point for the transcript hash
     * over the partial ClientHello. */
    out->psk_partial_ch_off = (size_t)(p - raw_base);

    uint16_t bs_total;
    if (rd_u16(&p, &rem, &bs_total) != 0)         return -1;
    if (bs_total < 33 || rem < bs_total)          return -1;
    /* The pre_shared_key extension MUST consume exactly its entire
     * extension_data (no trailing bytes). */
    if (rem != bs_total)                          return -1;

    {
        const uint8_t* lp = p;
        size_t         lr = bs_total;
        unsigned       n  = 0;
        while (lr > 0) {
            uint8_t bl;
            if (rd_u8(&lp, &lr, &bl) != 0)        return -1;
            if (bl < 32 || lr < bl)               return -1;
            size_t off_in_raw = (size_t)(lp - raw_base);
            if (off_in_raw > raw_total)           return -1;
            if (n < TLS13_PSK_MAX_OFFERS) {
                out->psk_binder_off[n] = off_in_raw;
                out->psk_binder_len[n] = bl;
            }
            n++;
            if (rd_skip(&lp, &lr, bl) != 0)       return -1;
        }
        if (n != out->psk_offer_count)            return -1;   /* must match */
    }

    out->psk_present = 1;
    return 0;
}

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
        case 0x000d:                  /* signature_algorithms (RFC 8446 §4.2.3) */
        case 0x0032: {                /* signature_algorithms_cert (RFC 8446 §4.2.3a) */
            /*
             * Wire form (both extensions share the layout):
             *   u16 list_len
             *   u16 algos[list_len/2]
             *
             * For ed25519-only servers we want to know that 0x0807
             * appears in signature_algorithms (covers both signing
             * and cert selection unless the client also sent
             * signature_algorithms_cert, in which case we require
             * 0x0807 in BOTH). For Commit A we model this as: any
             * sighting of 0x0807 in either list flips offers_ed25519
             * on. The stricter "must appear in both lists when both
             * present" rule is layered in the engine itself, where
             * we have config context.
             */
            uint16_t list_len;
            if (rd_u16(&eb, &er, &list_len) != 0) return -1;
            if (list_len & 1u) return -1;            /* must be even */
            if (er < list_len) return -1;
            const uint8_t* lp = eb;
            size_t         lr = list_len;
            while (lr >= 2) {
                uint16_t alg;
                if (rd_u16(&lp, &lr, &alg) != 0) return -1;
                if (alg == TLS13_SIG_SCHEME_ED25519) out->offers_ed25519 = 1;
            }
            if (lr != 0) return -1;                  /* exact consumption */
            break;
        }
        default:
            /* Ignore unrecognised extensions (forward compat). */
            break;
        case 0x002a:                  /* early_data (CH variant: empty body) */
            /* RFC 8446 §4.2.10: in CH the extension_data is empty. */
            if (er != 0) return -1;
            out->offers_early_data = 1;
            break;
        case 0x002d: {                /* psk_key_exchange_modes (RFC 8446 §4.2.9) */
            uint8_t list_len;
            if (rd_u8(&eb, &er, &list_len) != 0) return -1;
            if (list_len < 1 || er < list_len)   return -1;
            for (uint8_t i = 0; i < list_len; i++) {
                if (eb[i] == 1 /* psk_dhe_ke */) out->psk_dhe_ke_offered = 1;
            }
            break;
        }
        case 0x0029: {                /* pre_shared_key (RFC 8446 §4.2.11) */
            /* MUST be the LAST extension in CH per §4.2.11. */
            if (rem != 0) return -1;
            if (parse_psk_extension(eb, er, out->raw, out->raw_len, out) != 0) return -1;
            break;
        }
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

    /* legacy_session_id<0..32> — capture it (RFC 8446 §4.1.2 caps at 32);
     * server MUST echo it in ServerHello in compat mode (§D.4). */
    uint8_t sid_len;
    if (rd_u8(&p, &rem, &sid_len) != 0)              return -1;
    if (sid_len > 32)                                return -1;
    if (rem < sid_len)                               return -1;
    if (sid_len > 0) memcpy(out->legacy_session_id, p, sid_len);
    out->legacy_session_id_len = sid_len;
    if (rd_skip(&p, &rem, sid_len) != 0)             return -1;

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

    /* legacy_compression_methods<1..2^8-1> — RFC 8446 §4.1.2 requires
     * a single null compression method (0x00). */
    uint8_t cm_len;
    if (rd_u8(&p, &rem, &cm_len) != 0)               return -1;
    if (cm_len < 1 || rem < cm_len)                  return -1;
    {
        int has_null = 0;
        for (uint8_t i = 0; i < cm_len; i++) {
            if (p[i] == 0x00) { has_null = 1; break; }
        }
        if (!has_null) return -1;
    }
    if (rd_skip(&p, &rem, cm_len) != 0)              return -1;

    /* extensions<8..2^16-1> */
    uint16_t ext_total;
    if (rd_u16(&p, &rem, &ext_total) != 0)           return -1;
    if (ext_total != rem)                            return -1;

    return parse_extensions(p, ext_total, out);
}

/* ------------------ ServerHello builder ------------------ */

int tls13_build_server_hello(uint8_t* out, size_t out_cap,
                             const uint8_t server_random[TLS13_RANDOM_LEN],
                             const uint8_t our_pubkey[32],
                             const uint8_t* session_id,
                             uint8_t session_id_len) {
    return tls13_build_server_hello_psk(out, out_cap, server_random,
                                        our_pubkey, session_id,
                                        session_id_len, -1);
}

int tls13_build_server_hello_psk(uint8_t* out, size_t out_cap,
                                 const uint8_t server_random[TLS13_RANDOM_LEN],
                                 const uint8_t our_pubkey[32],
                                 const uint8_t* session_id,
                                 uint8_t session_id_len,
                                 int selected_psk_identity) {
    if (!out || !server_random || !our_pubkey) return -1;
    if (session_id_len > 32) return -1;
    if (session_id_len > 0 && !session_id) return -1;
    if (selected_psk_identity > 0xffff) return -1;

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
    /* legacy_session_id_echo<0..32>: echo the client's session_id
     * verbatim (compat mode — TLS 1.2 clients / browsers expect this). */
    if (wr_u8(&p, &rem, session_id_len) != 0) return -1;
    if (session_id_len > 0) {
        if (wr_bytes(&p, &rem, session_id, session_id_len) != 0) return -1;
    }
    /* cipher_suite */
    if (wr_u16(&p, &rem, TLS13_CHACHA20_POLY1305_SHA256) != 0) return -1;
    /* legacy_compression_method */
    if (wr_u8(&p, &rem, 0) != 0)              return -1;

    /* extensions: supported_versions (6) + key_share (40) + maybe psk (8)
     *   pre_shared_key (SH variant): type(2) + size(2) + selected_identity(2) = 6
     *   wait, that's 8 with type+size header. */
    uint16_t ext_total = 46;
    if (selected_psk_identity >= 0) ext_total += 6 + 2;  /* hdr(4)+body(2) = 6, +2... */
    /* Recompute: ext = type(2) + size(2) + body. body for PSK SH = 2.
     * So extension occupies 4 + 2 = 6 bytes. */
    /* Reset and recompute cleanly. */
    ext_total = 46;
    if (selected_psk_identity >= 0) ext_total = 46 + 6;
    if (wr_u16(&p, &rem, ext_total) != 0) return -1;

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

    /* pre_shared_key (SH variant): selected_identity uint16. */
    if (selected_psk_identity >= 0) {
        if (wr_u16(&p, &rem, 0x0029) != 0) return -1;
        if (wr_u16(&p, &rem, 2)      != 0) return -1;
        if (wr_u16(&p, &rem, (uint16_t)selected_psk_identity) != 0) return -1;
    }

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

int tls13_build_encrypted_extensions_ex(uint8_t* out, size_t out_cap,
                                        int include_early_data) {
    if (!include_early_data) return tls13_build_encrypted_extensions(out, out_cap);
    /* EE with one extension: early_data (type 0x002a, body empty).
     * Per RFC 8446 §4.2.10 the EE early_data extension body is empty. */
    if (!out || out_cap < 10) return -1;
    out[0] = 0x08;
    out[1] = 0x00; out[2] = 0x00; out[3] = 0x06;   /* body = ext_list_len(2) + ext(4) = 6 */
    out[4] = 0x00; out[5] = 0x04;                   /* ext_list_len = 4 */
    out[6] = 0x00; out[7] = 0x2a;                   /* type = early_data */
    out[8] = 0x00; out[9] = 0x00;                   /* ext_data length = 0 */
    return 10;
}

int tls13_build_certificate(uint8_t* out, size_t out_cap,
                            const uint8_t* chain_der,
                            const size_t* cert_lens,
                            unsigned n_certs) {
    if (!out || (n_certs > 0 && (!chain_der || !cert_lens))) return -1;

    /* Compute the body length up front for bounds checks:
     *   1 (cert_request_context len = 0)
     *   3 (certificate_list length, u24)
     *   sum( 3 (cert_data len, u24) + cert_lens[i] + 2 (extensions len = 0) )
     */
    uint64_t cl_total = 0;
    for (unsigned i = 0; i < n_certs; i++) {
        if (cert_lens[i] > 0xFFFFFFu) return -1;        /* per-cert u24 */
        cl_total += 3u + (uint64_t)cert_lens[i] + 2u;
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
        size_t cl = cert_lens[i];
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

/* ---------------- NewSessionTicket (RFC 8446 §4.6.1) ---------------- */

int tls13_build_new_session_ticket(uint8_t* out, size_t out_cap,
                                   uint32_t lifetime_s,
                                   uint32_t age_add,
                                   const uint8_t* ticket_nonce,
                                   size_t nonce_len,
                                   const uint8_t* ticket_id,
                                   size_t id_len) {
    if (!out || !ticket_nonce || !ticket_id) return -1;
    if (nonce_len == 0 || nonce_len > 255)   return -1;
    if (id_len    == 0 || id_len    > 0xffff) return -1;
    /* body = 4 + 4 + 1 + nonce + 2 + id + 2 (empty exts) */
    size_t body = 4 + 4 + 1 + nonce_len + 2 + id_len + 2;
    if (body > 0xffffffu)   return -1;
    if (out_cap < 4 + body) return -1;

    uint8_t* p = out;
    *p++ = 0x04;                                  /* HS type = NewSessionTicket */
    *p++ = (uint8_t)((body >> 16) & 0xff);
    *p++ = (uint8_t)((body >>  8) & 0xff);
    *p++ = (uint8_t)( body        & 0xff);

    *p++ = (uint8_t)((lifetime_s >> 24) & 0xff);
    *p++ = (uint8_t)((lifetime_s >> 16) & 0xff);
    *p++ = (uint8_t)((lifetime_s >>  8) & 0xff);
    *p++ = (uint8_t)( lifetime_s        & 0xff);

    *p++ = (uint8_t)((age_add >> 24) & 0xff);
    *p++ = (uint8_t)((age_add >> 16) & 0xff);
    *p++ = (uint8_t)((age_add >>  8) & 0xff);
    *p++ = (uint8_t)( age_add        & 0xff);

    *p++ = (uint8_t)nonce_len;
    memcpy(p, ticket_nonce, nonce_len); p += nonce_len;

    *p++ = (uint8_t)((id_len >> 8) & 0xff);
    *p++ = (uint8_t)( id_len       & 0xff);
    memcpy(p, ticket_id, id_len); p += id_len;

    /* Empty extensions block. */
    *p++ = 0x00; *p++ = 0x00;

    return (int)(p - out);
}

int tls13_derive_resumption_psk(const uint8_t resumption_master_secret[32],
                                const uint8_t* ticket_nonce, size_t nonce_len,
                                uint8_t psk[32]) {
    if (!resumption_master_secret || !ticket_nonce || !psk) return -1;
    if (nonce_len == 0 || nonce_len > 255) return -1;
    /* PSK = HKDF-Expand-Label(RMS, "resumption", ticket_nonce, 32). */
    if (tls13_hkdf_expand_label(resumption_master_secret, "resumption",
                                ticket_nonce, nonce_len,
                                psk, 32) != 0) return -1;
    return 0;
}

/* ---------------- CertificateVerify (RFC 8446 §4.4.3) ---------------- */

int tls13_build_certificate_verify_signed_data(uint8_t out[TLS13_CV_SIGNED_LEN],
                                               const uint8_t transcript_hash[32],
                                               int is_server) {
    if (!out || !transcript_hash) return -1;

    /* 64 bytes of 0x20 padding. */
    memset(out, 0x20, 64);

    /* 33-byte ASCII context string (no NUL). */
    const char* label = is_server ? TLS13_CV_LABEL_SERVER
                                  : TLS13_CV_LABEL_CLIENT;
    /* Compile-time-ish sanity: both labels are 33 bytes. */
    memcpy(out + 64, label, 33);

    /* 1-byte 0x00 separator. */
    out[64 + 33] = 0x00;

    /* 32-byte transcript hash. */
    memcpy(out + 64 + 33 + 1, transcript_hash, 32);
    return 0;
}

int tls13_build_certificate_verify(uint8_t* out, size_t out_cap,
                                   const uint8_t transcript_hash[32],
                                   const uint8_t seed[32]) {
    if (!out || !transcript_hash || !seed) return -1;
    /* Wire size = 4 (handshake header) + 2 (sig_scheme) + 2 (sig_len)
     *           + 64 (signature) = 72 bytes. */
    const size_t wire_len = 4u + 2u + 2u + ED25519_SIG_LEN;
    if (out_cap < wire_len) return -1;

    /* Build the signed prefix on the stack. */
    uint8_t signed_data[TLS13_CV_SIGNED_LEN];
    if (tls13_build_certificate_verify_signed_data(signed_data,
                                                   transcript_hash, 1) != 0) {
        return -1;
    }

    /* Derive pubkey from seed. ~50us; one-shot per handshake.
     * (Caller could pre-derive and cache it on cert load if needed.) */
    uint8_t pubkey[ED25519_PUBKEY_LEN];
    ed25519_pubkey_from_seed(pubkey, seed);

    uint8_t sig[ED25519_SIG_LEN];
    ed25519_sign(sig, signed_data, TLS13_CV_SIGNED_LEN, seed, pubkey);

    /* Wipe the derived pubkey buffer + signed-data buffer. signed_data
     * isn't a secret (it's transcript-hash-prefixed) but the seed-derived
     * pubkey isn't either. We wipe defensively to keep the function's
     * stack frame clean. The 'seed' input is owned by the caller. */
    secure_zero(signed_data, sizeof(signed_data));

    /* Now write the wire bytes:
     *   handshake header  : 0x0f, body_len_24 = 4 + 64 = 68
     *   sig_scheme        : 0x0807 (ed25519)
     *   signature length  : 0x0040 (= 64)
     *   signature         : 64 bytes
     */
    uint8_t* p = out;
    *p++ = 0x0f;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = (uint8_t)(2u + 2u + ED25519_SIG_LEN);    /* = 0x44 = 68 */
    *p++ = (uint8_t)(TLS13_SIG_SCHEME_ED25519 >> 8);
    *p++ = (uint8_t)(TLS13_SIG_SCHEME_ED25519 & 0xFF);
    *p++ = 0x00;
    *p++ = (uint8_t)ED25519_SIG_LEN;                /* = 0x40 */
    memcpy(p, sig, ED25519_SIG_LEN);
    p += ED25519_SIG_LEN;

    /* Wipe sig (defence-in-depth — sig isn't really secret but
     * keeping locals clean is cheap). */
    secure_zero(sig, sizeof(sig));
    secure_zero(pubkey, sizeof(pubkey));

    return (int)(p - out);
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

int tls13_compute_application_secrets(const uint8_t handshake_secret[32],
                                      const uint8_t transcript_hash_through_server_finished[32],
                                      uint8_t master_secret[32],
                                      uint8_t client_ap_traffic_secret[32],
                                      uint8_t server_ap_traffic_secret[32]) {
    uint8_t zero32[32] = {0};
    uint8_t derived[32];
    uint8_t empty_hash[32];

    /* derived = Derive-Secret(handshake_secret, "derived", "") */
    sha256("", 0, empty_hash);
    if (tls13_hkdf_expand_label(handshake_secret, "derived",
                                empty_hash, sizeof(empty_hash),
                                derived, sizeof(derived)) != 0) return -1;

    /* master_secret = HKDF-Extract(salt=derived, IKM=00..00) */
    hkdf_extract(derived, sizeof(derived),
                 zero32,  sizeof(zero32),
                 master_secret);

    if (tls13_hkdf_expand_label(master_secret, "c ap traffic",
                                transcript_hash_through_server_finished, 32,
                                client_ap_traffic_secret, 32) != 0) return -1;
    if (tls13_hkdf_expand_label(master_secret, "s ap traffic",
                                transcript_hash_through_server_finished, 32,
                                server_ap_traffic_secret, 32) != 0) return -1;

    secure_zero(derived, sizeof(derived));
    return 0;
}

int tls13_compute_resumption_master_secret(
    const uint8_t master_secret[32],
    const uint8_t transcript_hash_through_client_finished[32],
    uint8_t       resumption_master_secret[32]) {
    /* Derive-Secret(master_secret, "res master", H(CH..cFin)) */
    if (tls13_hkdf_expand_label(master_secret, "res master",
                                transcript_hash_through_client_finished, 32,
                                resumption_master_secret, 32) != 0) return -1;
    return 0;
}

/* ---------------- Early-secret schedule (RFC 8446 §7.1) ---------------- */

int tls13_compute_early_secret(const uint8_t* psk, size_t psk_len,
                               uint8_t early_secret[32]) {
    if (!early_secret) return -1;
    /* early_secret = HKDF-Extract(salt=00..00, IKM=PSK or 00..00). */
    uint8_t zero32[32] = {0};
    const uint8_t* ikm     = psk     ? psk     : zero32;
    size_t         ikm_len = psk     ? psk_len : sizeof(zero32);
    if (psk && psk_len == 0) { ikm = zero32; ikm_len = sizeof(zero32); }
    hkdf_extract(zero32, sizeof(zero32), ikm, ikm_len, early_secret);
    return 0;
}

int tls13_compute_binder_key(const uint8_t early_secret[32],
                             int is_external,
                             uint8_t binder_key[32]) {
    if (!early_secret || !binder_key) return -1;
    /* binder_key = Derive-Secret(early_secret,
     *               is_external ? "ext binder" : "res binder", "")
     * "" -> hash of empty string. */
    uint8_t empty_hash[32];
    sha256("", 0, empty_hash);
    const char* label = is_external ? "ext binder" : "res binder";
    if (tls13_hkdf_expand_label(early_secret, label,
                                empty_hash, sizeof(empty_hash),
                                binder_key, 32) != 0) return -1;
    return 0;
}

int tls13_compute_psk_binder(const uint8_t binder_key[32],
                             const uint8_t partial_ch_hash[32],
                             uint8_t binder_out[32]) {
    if (!binder_key || !partial_ch_hash || !binder_out) return -1;
    /* Per RFC 8446 §4.2.11.2 the binder is a Finished-style HMAC:
     *   finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
     *   binder       = HMAC-SHA256(finished_key, partial_ch_hash)
     * (We reuse tls13_compute_finished — same construction.) */
    return tls13_compute_finished(binder_key, partial_ch_hash, binder_out);
}

int tls13_compute_client_early_traffic_secret(
    const uint8_t early_secret[32],
    const uint8_t transcript_hash_through_client_hello[32],
    uint8_t       client_early_traffic_secret[32]) {
    if (!early_secret || !transcript_hash_through_client_hello
        || !client_early_traffic_secret) return -1;
    /* Derive-Secret(early_secret, "c e traffic", H(CH)) */
    if (tls13_hkdf_expand_label(early_secret, "c e traffic",
                                transcript_hash_through_client_hello, 32,
                                client_early_traffic_secret, 32) != 0) return -1;
    return 0;
}

int tls13_compute_handshake_secrets_psk(const uint8_t* psk, size_t psk_len,
                                        const uint8_t ecdhe_shared[32],
                                        const uint8_t transcript_hash[32],
                                        uint8_t handshake_secret[32],
                                        uint8_t client_hs_traffic_secret[32],
                                        uint8_t server_hs_traffic_secret[32]) {
    /* Same derivation as tls13_compute_handshake_secrets, but the
     * early_secret is extracted from a real PSK (rather than the
     * all-zero IKM). RFC 8446 §7.1. */
    uint8_t early_secret[32];
    uint8_t derived[32];
    uint8_t empty_hash[32];

    if (tls13_compute_early_secret(psk, psk_len, early_secret) != 0) return -1;

    sha256("", 0, empty_hash);
    if (tls13_hkdf_expand_label(early_secret, "derived",
                                empty_hash, sizeof(empty_hash),
                                derived, sizeof(derived)) != 0) {
        secure_zero(early_secret, sizeof(early_secret));
        return -1;
    }
    secure_zero(early_secret, sizeof(early_secret));

    hkdf_extract(derived, sizeof(derived),
                 ecdhe_shared, 32, handshake_secret);

    if (tls13_hkdf_expand_label(handshake_secret, "c hs traffic",
                                transcript_hash, 32,
                                client_hs_traffic_secret, 32) != 0) {
        secure_zero(derived, sizeof(derived));
        return -1;
    }
    if (tls13_hkdf_expand_label(handshake_secret, "s hs traffic",
                                transcript_hash, 32,
                                server_hs_traffic_secret, 32) != 0) {
        secure_zero(derived, sizeof(derived));
        return -1;
    }
    secure_zero(derived, sizeof(derived));
    return 0;
}
