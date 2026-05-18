/* QUIC v1 Initial packet build/parse + header protection.
 * RFC 9000 §17.2.2 + RFC 9001 §5.4. */
#include "packet.h"

#include "varint.h"
#include "../crypto/aes.h"
#include "../crypto/aes_gcm.h"

#include <string.h>

#define QUIC_V1_VERSION  0x00000001u
#define QUIC_PKT_MIN     1200u
#define QUIC_TAG_LEN     16u
#define QUIC_HP_SAMPLE_LEN 16u

/* Reconstruct the per-packet AEAD nonce by XOR-ing the truncated
 * packet number into the right-aligned IV (RFC 9001 §5.3). */
static void make_nonce(const uint8_t iv[QUIC_INITIAL_IV_LEN],
                       uint64_t pn,
                       uint8_t nonce[QUIC_INITIAL_IV_LEN]) {
    memcpy(nonce, iv, QUIC_INITIAL_IV_LEN);
    for (int i = 0; i < 8; i++) {
        nonce[QUIC_INITIAL_IV_LEN - 1 - i] ^= (uint8_t)(pn >> (8 * i));
    }
}

/* Apply header protection mask (RFC 9001 §5.4.1). For Initial we
 * always mask the low 4 bits of byte0 (long header). */
static void hp_apply(const uint8_t hp_key[QUIC_INITIAL_HP_LEN],
                     const uint8_t sample[QUIC_HP_SAMPLE_LEN],
                     uint8_t* byte0,
                     uint8_t* pn_bytes,
                     unsigned pn_len) {
    aes128_ctx_t aes;
    aes128_init(&aes, hp_key);
    uint8_t mask[16];
    aes128_encrypt_block(&aes, sample, mask);

    *byte0 ^= mask[0] & 0x0f;
    for (unsigned i = 0; i < pn_len; i++) {
        pn_bytes[i] ^= mask[1 + i];
    }
}

size_t quic_initial_build(uint8_t* out, size_t out_cap,
                          const quic_initial_pkt_t* pkt,
                          const quic_initial_keys_t* keys,
                          int pad_to_min) {
    if (pkt->dcid_len > QUIC_MAX_CID_LEN) return 0;
    if (pkt->scid_len > QUIC_MAX_CID_LEN) return 0;
    if (pkt->token_len > QUIC_MAX_TOKEN_LEN) return 0;
    if (pkt->pn_len < 1 || pkt->pn_len > 4) return 0;
    if (pkt->version != QUIC_V1_VERSION) return 0;

    /* Compute payload length (frames + padding). The wire `Length`
     * field covers PN bytes + protected payload + AEAD tag. */
    size_t frame_len = pkt->payload_len;

    /* First, lay out the unprotected header so we know its size. */
    size_t off = 0;
    if (off + 1 > out_cap) return 0;
    uint8_t byte0 = (uint8_t)(0xc0u                 /* form=1, fixed=1, type=Initial(00) */
                              | (uint8_t)(pkt->pn_len - 1));
    out[off++] = byte0;

    if (off + 4 > out_cap) return 0;
    out[off++] = (uint8_t)(pkt->version >> 24);
    out[off++] = (uint8_t)(pkt->version >> 16);
    out[off++] = (uint8_t)(pkt->version >>  8);
    out[off++] = (uint8_t)(pkt->version);

    if (off + 1 + pkt->dcid_len > out_cap) return 0;
    out[off++] = (uint8_t)pkt->dcid_len;
    memcpy(out + off, pkt->dcid, pkt->dcid_len); off += pkt->dcid_len;

    if (off + 1 + pkt->scid_len > out_cap) return 0;
    out[off++] = (uint8_t)pkt->scid_len;
    memcpy(out + off, pkt->scid, pkt->scid_len); off += pkt->scid_len;

    /* Token (Initial-only). */
    uint8_t tlen_buf[8];
    size_t tlen_n = quic_varint_encode(tlen_buf, sizeof tlen_buf, pkt->token_len);
    if (off + tlen_n + pkt->token_len > out_cap) return 0;
    memcpy(out + off, tlen_buf, tlen_n); off += tlen_n;
    if (pkt->token_len) {
        memcpy(out + off, pkt->token, pkt->token_len);
        off += pkt->token_len;
    }

    /* Decide how much padding to append AFTER the frame payload to
     * meet the 1200-byte minimum (when requested). */
    size_t pad = 0;
    if (pad_to_min) {
        /* Estimate total: header_so_far + length_field(2) + pn_len
         * + frame_len + tag. Use 2-byte length field as conservative. */
        size_t length_field_size = 2;
        size_t projected = off + length_field_size + pkt->pn_len + frame_len + QUIC_TAG_LEN;
        if (projected < QUIC_PKT_MIN) {
            pad = QUIC_PKT_MIN - projected;
        }
    }
    size_t prot_pt_len = frame_len + pad;            /* unprotected plaintext */
    size_t length_value = pkt->pn_len + prot_pt_len + QUIC_TAG_LEN;

    /* Length field: use 2-byte varint always (covers up to 16383)
     * which is enough for any datagram we'll emit. */
    if (length_value > 0x3fff) return 0;
    if (off + 2 > out_cap) return 0;
    out[off++] = (uint8_t)(0x40u | ((length_value >> 8) & 0x3f));
    out[off++] = (uint8_t)(length_value);

    /* Packet number (truncated, big-endian). */
    size_t pn_off = off;
    if (off + pkt->pn_len > out_cap) return 0;
    for (unsigned i = 0; i < pkt->pn_len; i++) {
        out[off + i] = (uint8_t)(pkt->pn >> (8 * (pkt->pn_len - 1 - i)));
    }
    off += pkt->pn_len;

    /* Plaintext payload (frames + padding). */
    if (off + prot_pt_len + QUIC_TAG_LEN > out_cap) return 0;
    if (frame_len) memcpy(out + off, pkt->payload, frame_len);
    if (pad) memset(out + off + frame_len, 0, pad);    /* PADDING frames = 0x00 */
    size_t pt_off = off;
    off += prot_pt_len;

    /* AEAD seal: AAD = unprotected header (offset 0 .. pt_off),
     * plaintext = pt_off .. pt_off+prot_pt_len, tag goes after. */
    uint8_t nonce[QUIC_INITIAL_IV_LEN];
    make_nonce(keys->iv, pkt->pn, nonce);
    aes128_gcm_seal(keys->key, nonce,
                    out, pt_off,                     /* aad = full header */
                    out + pt_off, prot_pt_len,
                    out + pt_off,                    /* ct in place */
                    out + pt_off + prot_pt_len);     /* tag */
    off += QUIC_TAG_LEN;

    /* Header protection: sample = ciphertext starting at pn_off+4. */
    if (pn_off + 4 + QUIC_HP_SAMPLE_LEN > off) return 0;
    hp_apply(keys->hp, out + pn_off + 4,
             &out[0], out + pn_off, pkt->pn_len);

    return off;
}

int quic_initial_parse(const uint8_t* in, size_t in_len,
                       const quic_initial_keys_t* keys,
                       quic_initial_pkt_t* pkt,
                       uint8_t* scratch, size_t scratch_cap) {
    if (in_len < 7) return -1;
    /* Copy first byte; we'll undo HP mask on a local copy. */
    uint8_t byte0 = in[0];
    /* Long-header form (high bit set), fixed bit set, type=Initial(00). */
    if ((byte0 & 0xf0) != 0xc0) return -1;

    uint32_t ver = ((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) |
                   ((uint32_t)in[3] <<  8) |  (uint32_t)in[4];
    if (ver != QUIC_V1_VERSION) return -1;

    size_t off = 5;
    if (off + 1 > in_len) return -1;
    size_t dcid_len = in[off++];
    if (dcid_len > QUIC_MAX_CID_LEN || off + dcid_len > in_len) return -1;
    const uint8_t* dcid = in + off; off += dcid_len;

    if (off + 1 > in_len) return -1;
    size_t scid_len = in[off++];
    if (scid_len > QUIC_MAX_CID_LEN || off + scid_len > in_len) return -1;
    const uint8_t* scid = in + off; off += scid_len;

    /* Initial packets carry a Token (varint length + bytes). */
    uint64_t token_len_v;
    size_t   token_len_n = quic_varint_decode(in + off, in_len - off, &token_len_v);
    if (token_len_n == 0) return -1;
    off += token_len_n;
    if (token_len_v > QUIC_MAX_TOKEN_LEN) return -1;
    if (off + token_len_v > in_len) return -1;
    const uint8_t* token = in + off; off += (size_t)token_len_v;

    /* Length (varint) covers PN + protected payload + tag. */
    uint64_t length_v;
    size_t   length_n = quic_varint_decode(in + off, in_len - off, &length_v);
    if (length_n == 0) return -1;
    off += length_n;
    if (off + length_v > in_len) return -1;

    size_t pn_off = off;
    /* HP requires sample at pn_off+4. */
    if (pn_off + 4 + QUIC_HP_SAMPLE_LEN > in_len) return -1;

    /* Compute mask (header NOT yet de-protected). */
    aes128_ctx_t aes;
    aes128_init(&aes, keys->hp);
    uint8_t mask[16];
    aes128_encrypt_block(&aes, in + pn_off + 4, mask);

    /* Apply mask to recover real byte0 (low 4 bits) and PN length. */
    uint8_t real_byte0 = byte0 ^ (mask[0] & 0x0f);
    unsigned pn_len = (real_byte0 & 0x03) + 1;

    /* Recover packet-number bytes. */
    uint8_t pn_bytes[4] = {0};
    for (unsigned i = 0; i < pn_len; i++) {
        pn_bytes[i] = in[pn_off + i] ^ mask[1 + i];
    }

    uint64_t pn = 0;
    for (unsigned i = 0; i < pn_len; i++) {
        pn = (pn << 8) | pn_bytes[i];
    }

    /* Reconstruct the unprotected header in scratch (AAD must be
     * the unprotected bytes per RFC 9001 §5.3). */
    size_t hdr_len = pn_off + pn_len;
    if (hdr_len > scratch_cap) return -1;
    memcpy(scratch, in, hdr_len);
    scratch[0]      = real_byte0;
    for (unsigned i = 0; i < pn_len; i++) scratch[pn_off + i] = pn_bytes[i];

    /* Decrypt AEAD. */
    size_t payload_off = pn_off + pn_len;
    size_t enc_len     = (size_t)length_v - pn_len;
    if (enc_len < QUIC_TAG_LEN) return -1;
    size_t ct_len      = enc_len - QUIC_TAG_LEN;
    if (hdr_len + ct_len > scratch_cap) return -1;

    uint8_t nonce[QUIC_INITIAL_IV_LEN];
    make_nonce(keys->iv, pn, nonce);
    int rc = aes128_gcm_open(keys->key, nonce,
                             scratch, hdr_len,
                             in + payload_off, ct_len,
                             in + payload_off + ct_len,
                             scratch + hdr_len);
    if (rc != 0) return -1;

    pkt->version = ver;
    if (dcid_len > sizeof pkt->dcid) return -1;
    memcpy(pkt->dcid, dcid, dcid_len); pkt->dcid_len = dcid_len;
    if (scid_len > sizeof pkt->scid) return -1;
    memcpy(pkt->scid, scid, scid_len); pkt->scid_len = scid_len;
    if (token_len_v > sizeof pkt->token) return -1;
    if (token_len_v) memcpy(pkt->token, token, (size_t)token_len_v);
    pkt->token_len = (size_t)token_len_v;
    pkt->pn        = pn;
    pkt->pn_len    = pn_len;
    pkt->payload   = scratch + hdr_len;
    pkt->payload_len = ct_len;
    return 0;
}

/* ---- Handshake long-header packets (RFC 9000 §17.2.4) ----- */

size_t quic_handshake_build(uint8_t* out, size_t out_cap,
                            const quic_handshake_pkt_t* pkt,
                            const quic_handshake_keys_t* keys) {
    if (pkt->dcid_len > QUIC_MAX_CID_LEN) return 0;
    if (pkt->scid_len > QUIC_MAX_CID_LEN) return 0;
    if (pkt->pn_len < 1 || pkt->pn_len > 4) return 0;
    if (pkt->version != QUIC_V1_VERSION) return 0;

    size_t frame_len = pkt->payload_len;

    size_t off = 0;
    if (off + 1 > out_cap) return 0;
    /* form=1, fixed=1, type=Handshake(10), reserved(00), pn_len bits. */
    uint8_t byte0 = (uint8_t)(0xe0u | (uint8_t)(pkt->pn_len - 1));
    out[off++] = byte0;

    if (off + 4 > out_cap) return 0;
    out[off++] = (uint8_t)(pkt->version >> 24);
    out[off++] = (uint8_t)(pkt->version >> 16);
    out[off++] = (uint8_t)(pkt->version >>  8);
    out[off++] = (uint8_t)(pkt->version);

    if (off + 1 + pkt->dcid_len > out_cap) return 0;
    out[off++] = (uint8_t)pkt->dcid_len;
    memcpy(out + off, pkt->dcid, pkt->dcid_len); off += pkt->dcid_len;

    if (off + 1 + pkt->scid_len > out_cap) return 0;
    out[off++] = (uint8_t)pkt->scid_len;
    memcpy(out + off, pkt->scid, pkt->scid_len); off += pkt->scid_len;

    /* No Token field for Handshake packets. */

    size_t prot_pt_len = frame_len;
    size_t length_value = pkt->pn_len + prot_pt_len + QUIC_TAG_LEN;

    if (length_value > 0x3fff) return 0;
    if (off + 2 > out_cap) return 0;
    out[off++] = (uint8_t)(0x40u | ((length_value >> 8) & 0x3f));
    out[off++] = (uint8_t)(length_value);

    size_t pn_off = off;
    if (off + pkt->pn_len > out_cap) return 0;
    for (unsigned i = 0; i < pkt->pn_len; i++) {
        out[off + i] = (uint8_t)(pkt->pn >> (8 * (pkt->pn_len - 1 - i)));
    }
    off += pkt->pn_len;

    if (off + prot_pt_len + QUIC_TAG_LEN > out_cap) return 0;
    if (frame_len) memcpy(out + off, pkt->payload, frame_len);
    size_t pt_off = off;
    off += prot_pt_len;

    uint8_t nonce[QUIC_INITIAL_IV_LEN];
    make_nonce(keys->iv, pkt->pn, nonce);
    aes128_gcm_seal(keys->key, nonce,
                    out, pt_off,
                    out + pt_off, prot_pt_len,
                    out + pt_off,
                    out + pt_off + prot_pt_len);
    off += QUIC_TAG_LEN;

    if (pn_off + 4 + QUIC_HP_SAMPLE_LEN > off) return 0;
    hp_apply(keys->hp, out + pn_off + 4,
             &out[0], out + pn_off, pkt->pn_len);

    return off;
}

int quic_handshake_parse(const uint8_t* in, size_t in_len,
                         const quic_handshake_keys_t* keys,
                         quic_handshake_pkt_t* pkt,
                         uint8_t* scratch, size_t scratch_cap) {
    if (in_len < 7) return -1;
    uint8_t byte0 = in[0];
    /* Long-header form, fixed bit set, type=Handshake(10). */
    if ((byte0 & 0xf0) != 0xe0) return -1;

    uint32_t ver = ((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) |
                   ((uint32_t)in[3] <<  8) |  (uint32_t)in[4];
    if (ver != QUIC_V1_VERSION) return -1;

    size_t off = 5;
    if (off + 1 > in_len) return -1;
    size_t dcid_len = in[off++];
    if (dcid_len > QUIC_MAX_CID_LEN || off + dcid_len > in_len) return -1;
    const uint8_t* dcid = in + off; off += dcid_len;

    if (off + 1 > in_len) return -1;
    size_t scid_len = in[off++];
    if (scid_len > QUIC_MAX_CID_LEN || off + scid_len > in_len) return -1;
    const uint8_t* scid = in + off; off += scid_len;

    /* No Token. */

    uint64_t length_v;
    size_t   length_n = quic_varint_decode(in + off, in_len - off, &length_v);
    if (length_n == 0) return -1;
    off += length_n;
    if (off + length_v > in_len) return -1;

    size_t pn_off = off;
    if (pn_off + 4 + QUIC_HP_SAMPLE_LEN > in_len) return -1;

    aes128_ctx_t aes;
    aes128_init(&aes, keys->hp);
    uint8_t mask[16];
    aes128_encrypt_block(&aes, in + pn_off + 4, mask);

    uint8_t real_byte0 = byte0 ^ (mask[0] & 0x0f);
    unsigned pn_len = (real_byte0 & 0x03) + 1;

    uint8_t pn_bytes[4] = {0};
    for (unsigned i = 0; i < pn_len; i++) {
        pn_bytes[i] = in[pn_off + i] ^ mask[1 + i];
    }
    uint64_t pn = 0;
    for (unsigned i = 0; i < pn_len; i++) pn = (pn << 8) | pn_bytes[i];

    size_t hdr_len = pn_off + pn_len;
    if (hdr_len > scratch_cap) return -1;
    memcpy(scratch, in, hdr_len);
    scratch[0] = real_byte0;
    for (unsigned i = 0; i < pn_len; i++) scratch[pn_off + i] = pn_bytes[i];

    size_t payload_off = pn_off + pn_len;
    size_t enc_len     = (size_t)length_v - pn_len;
    if (enc_len < QUIC_TAG_LEN) return -1;
    size_t ct_len      = enc_len - QUIC_TAG_LEN;
    if (hdr_len + ct_len > scratch_cap) return -1;

    uint8_t nonce[QUIC_INITIAL_IV_LEN];
    make_nonce(keys->iv, pn, nonce);
    int rc = aes128_gcm_open(keys->key, nonce,
                             scratch, hdr_len,
                             in + payload_off, ct_len,
                             in + payload_off + ct_len,
                             scratch + hdr_len);
    if (rc != 0) return -1;

    pkt->version = ver;
    if (dcid_len > sizeof pkt->dcid) return -1;
    memcpy(pkt->dcid, dcid, dcid_len); pkt->dcid_len = dcid_len;
    if (scid_len > sizeof pkt->scid) return -1;
    memcpy(pkt->scid, scid, scid_len); pkt->scid_len = scid_len;
    pkt->pn          = pn;
    pkt->pn_len      = pn_len;
    pkt->payload     = scratch + hdr_len;
    pkt->payload_len = ct_len;
    return 0;
}
