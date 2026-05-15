/*
 * QUIC v1 special packets + idle timer (RFC 9000 §10, §17.2.1) — phase 4d.
 */
#include "special.h"
#include <string.h>

size_t quic_stateless_reset_build(uint8_t* out, size_t cap,
                                  const uint8_t* rand_buf, size_t rand_len,
                                  const uint8_t token[QUIC_STATELESS_RESET_TOKEN_LEN])
{
    if (cap < QUIC_STATELESS_RESET_MIN) return 0;
    size_t pad = cap - QUIC_STATELESS_RESET_TOKEN_LEN;
    if (rand_len < pad) return 0;

    /* Short-header form: bit7=0, bit6=1 (fixed). Remaining bits random. */
    out[0] = 0x40 | (rand_buf[0] & 0x3f);
    if (pad > 1) memcpy(out + 1, rand_buf + 1, pad - 1);
    memcpy(out + pad, token, QUIC_STATELESS_RESET_TOKEN_LEN);
    return cap;
}

int quic_stateless_reset_match(const uint8_t* pkt, size_t pkt_len,
                               const uint8_t token[QUIC_STATELESS_RESET_TOKEN_LEN])
{
    if (pkt_len < QUIC_STATELESS_RESET_TOKEN_LEN) return 0;
    /* Constant-time tail comparison. */
    const uint8_t* tail = pkt + pkt_len - QUIC_STATELESS_RESET_TOKEN_LEN;
    uint8_t diff = 0;
    for (size_t i = 0; i < QUIC_STATELESS_RESET_TOKEN_LEN; i++) {
        diff |= tail[i] ^ token[i];
    }
    return diff == 0;
}

static int put_u8(uint8_t* o, size_t cap, size_t* off, uint8_t v) {
    if (*off >= cap) return 0;
    o[(*off)++] = v;
    return 1;
}
static int put_u32_be(uint8_t* o, size_t cap, size_t* off, uint32_t v) {
    if (cap - *off < 4) return 0;
    o[*off]   = (uint8_t)(v >> 24);
    o[*off+1] = (uint8_t)(v >> 16);
    o[*off+2] = (uint8_t)(v >>  8);
    o[*off+3] = (uint8_t)(v);
    *off += 4;
    return 1;
}
static int put_bytes(uint8_t* o, size_t cap, size_t* off,
                     const uint8_t* p, size_t n) {
    if (cap - *off < n) return 0;
    if (n) memcpy(o + *off, p, n);
    *off += n;
    return 1;
}

size_t quic_version_negotiation_build(uint8_t* out, size_t cap,
                                      uint8_t byte0_low7,
                                      const uint8_t* client_dcid, size_t client_dcid_len,
                                      const uint8_t* client_scid, size_t client_scid_len,
                                      const uint32_t* versions, size_t n_versions)
{
    if (client_dcid_len > 20 || client_scid_len > 20) return 0;
    if (n_versions == 0) return 0;
    size_t off = 0;
    /* Bit 7 must be set; lower bits are unspecified per §17.2.1. */
    if (!put_u8(out, cap, &off, (uint8_t)(0x80 | (byte0_low7 & 0x7f)))) return 0;
    if (!put_u32_be(out, cap, &off, 0u)) return 0;
    /* RFC 9000 §17.2.1 says VN packets echo the source-CID of the
     * triggering packet as the destination, and the dest-CID as source. */
    if (!put_u8(out, cap, &off, (uint8_t)client_scid_len)) return 0;
    if (!put_bytes(out, cap, &off, client_scid, client_scid_len)) return 0;
    if (!put_u8(out, cap, &off, (uint8_t)client_dcid_len)) return 0;
    if (!put_bytes(out, cap, &off, client_dcid, client_dcid_len)) return 0;
    for (size_t i = 0; i < n_versions; i++) {
        if (!put_u32_be(out, cap, &off, versions[i])) return 0;
    }
    return off;
}

int quic_idle_expired(uint64_t last_recv_us,
                      uint64_t idle_timeout_us,
                      uint64_t now_us)
{
    if (idle_timeout_us == 0) return 0;
    if (now_us < last_recv_us) return 0;       /* clock went backwards */
    return (now_us - last_recv_us) >= idle_timeout_us;
}
