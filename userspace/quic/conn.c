#include "conn.h"
#include "frames.h"
#include "tls_ext.h"
#include "keys.h"

#include <string.h>

void quic_conn_init_server(quic_conn_t* c)
{
    memset(c, 0, sizeof(*c));
    c->role = QUIC_ROLE_SERVER;
    quic_crypto_rx_init(&c->rx_initial,
                        c->rx_initial_data, sizeof c->rx_initial_data,
                        c->rx_initial_bm,   sizeof c->rx_initial_bm);
    quic_crypto_tx_init(&c->tx_initial);
    quic_crypto_rx_init(&c->rx_handshake,
                        c->rx_handshake_data, sizeof c->rx_handshake_data,
                        c->rx_handshake_bm,   sizeof c->rx_handshake_bm);
    quic_crypto_tx_init(&c->tx_handshake);
}

void quic_conn_force_derive_initial_keys(quic_conn_t* c,
                                         const uint8_t* dcid, size_t dcid_len)
{
    if (c->initial_keys_ready) return;
    /* The server uses the *server* side ("server in") of the keys to
     * encrypt outbound Initials and the *client* side ("client in")
     * to decrypt inbound. We need both; quic_initial_keys_t only
     * holds one direction, so the server-side conn keeps the CLIENT
     * keys here (used to decrypt rx). The tx side will store server
     * keys when we get to outbound (phase 5e2). */
    int is_server_for_decrypt = (c->role == QUIC_ROLE_SERVER) ? 0 : 1;
    quic_initial_derive(dcid, dcid_len, is_server_for_decrypt,
                        &c->initial_keys);
    c->initial_keys_ready = 1;
}

/* RFC 9000 §17.2.2: an Initial packet may contain only CRYPTO, ACK,
 * PADDING, PING, and CONNECTION_CLOSE frames. */
static int frame_allowed_in_initial(quic_frame_type_t t)
{
    switch (t) {
    case QUIC_FT_PADDING:
    case QUIC_FT_PING:
    case QUIC_FT_ACK:
    case QUIC_FT_ACK_ECN:
    case QUIC_FT_CRYPTO:
    case QUIC_FT_CONNECTION_CLOSE:    /* transport-level close */
        return 1;
    default:
        return 0;
    }
}

int quic_conn_recv_initial(quic_conn_t* c,
                           const uint8_t* datagram, size_t len)
{
    /* Peek the DCID without removing HP — quic_initial_parse needs the
     * keys, so on first receipt we derive them from the visible DCID
     * in the long-header. RFC 9000 §17.2: byte0 type bits + version(4)
     * + dcid_len(1) + dcid + scid_len(1) + scid + ... */
    if (len < 7) return -1;
    /* Long header bit must be set, fixed bit set; type bits = 00 (Initial). */
    if ((datagram[0] & 0xc0) != 0xc0) return -1;
    if ((datagram[0] & 0x30) != 0x00) return -1;
    /* Version must be QUIC v1. */
    uint32_t version = ((uint32_t)datagram[1] << 24) |
                       ((uint32_t)datagram[2] << 16) |
                       ((uint32_t)datagram[3] << 8)  |
                        (uint32_t)datagram[4];
    if (version != 0x00000001u) return -1;

    size_t off = 5;
    if (off >= len) return -1;
    uint8_t dcid_len = datagram[off++];
    if (dcid_len > QUIC_MAX_CID_LEN || (size_t)dcid_len > len - off) return -1;
    const uint8_t* dcid_ptr = datagram + off;
    off += dcid_len;

    if (off >= len) return -1;
    uint8_t scid_len = datagram[off++];
    if (scid_len > QUIC_MAX_CID_LEN || (size_t)scid_len > len - off) return -1;
    const uint8_t* scid_ptr = datagram + off;
    /* off += scid_len;   not needed beyond this point */

    /* Derive Initial keys from the DCID on the very first packet.
     * On subsequent packets the DCID must match — RFC 9000 §7.2 says
     * the server's chosen CID may change after the first response,
     * but until we send a response the client keeps using its initial
     * DCID. We pin to the first one we see for the lifetime of the
     * Initial epoch in this phase. */
    if (!c->initial_keys_ready) {
        quic_conn_force_derive_initial_keys(c, dcid_ptr, dcid_len);
        memcpy(c->peer_dcid, dcid_ptr, dcid_len);
        c->peer_dcid_len = dcid_len;
        memcpy(c->peer_scid, scid_ptr, scid_len);
        c->peer_scid_len = scid_len;
        c->peer_addrs_known = 1;
    } else {
        if (dcid_len != c->peer_dcid_len ||
            memcmp(dcid_ptr, c->peer_dcid, dcid_len) != 0) return -1;
    }

    /* Decrypt the packet. */
    quic_initial_pkt_t pkt;
    uint8_t scratch[2048];
    if (quic_initial_parse(datagram, len, &c->initial_keys,
                           &pkt, scratch, sizeof scratch) != 0) {
        return -1;
    }
    c->initial_pkts_rcvd++;

    /* Walk frames. */
    size_t fo = 0;
    while (fo < pkt.payload_len) {
        quic_frame_t f;
        size_t consumed = quic_frame_decode(pkt.payload + fo,
                                            pkt.payload_len - fo, &f);
        if (consumed == 0) break;
        if (consumed == QUIC_FRAME_DECODE_ERROR) return -1;
        fo += consumed;

        if (!frame_allowed_in_initial(f.type)) return -1;

        switch (f.type) {
        case QUIC_FT_CRYPTO: {
            int rc = quic_crypto_rx_stage(&c->rx_initial,
                                          f.u.crypto.offset,
                                          f.u.crypto.data,
                                          (size_t)f.u.crypto.length);
            if (rc < 0) return -1;
            c->initial_crypto_bytes_rcvd += f.u.crypto.length;
            c->initial_ack_eliciting_rcvd++;
            break;
        }
        case QUIC_FT_PING:
            c->initial_ack_eliciting_rcvd++;
            break;
        case QUIC_FT_ACK:
        case QUIC_FT_ACK_ECN:
        case QUIC_FT_PADDING:
        case QUIC_FT_CONNECTION_CLOSE:
            /* Accepted; full processing in later phases. */
            break;
        default:
            return -1;
        }
    }

    return 0;
}

const uint8_t* quic_conn_initial_rx_peek(const quic_conn_t* c, size_t* out_len)
{
    return quic_crypto_rx_peek(&c->rx_initial, out_len);
}

void quic_conn_initial_rx_advance(quic_conn_t* c, size_t n)
{
    quic_crypto_rx_advance(&c->rx_initial, n);
}

/* ---- phase 5e2: ClientHello + QUIC TP extraction --------------------
 *
 * Re-walks the CH header bytes (after parsing) to locate the
 * extensions block, then defers to quic_tls_ext_find_tp + quic_tp_decode.
 * The walk mirrors tls13_parse_client_hello so the offsets are exact.
 */
static int locate_ch_extensions_block(const uint8_t* msg, size_t msg_len,
                                      const uint8_t** ext_block,
                                      size_t* ext_block_len)
{
    /* hs_hdr(4) + legacy_version(2) + random(32) = 38 */
    if (msg_len < 38 + 1) return -1;
    size_t off = 38;

    uint8_t sid_len = msg[off++];
    if (sid_len > 32 || (size_t)sid_len > msg_len - off) return -1;
    off += sid_len;

    if (off + 2 > msg_len) return -1;
    uint16_t cs_len = ((uint16_t)msg[off] << 8) | msg[off + 1];
    off += 2;
    if ((cs_len & 1u) || (size_t)cs_len > msg_len - off) return -1;
    off += cs_len;

    if (off + 1 > msg_len) return -1;
    uint8_t cm_len = msg[off++];
    if (cm_len < 1 || (size_t)cm_len > msg_len - off) return -1;
    off += cm_len;

    if (off + 2 > msg_len) return -1;
    uint16_t ext_total = ((uint16_t)msg[off] << 8) | msg[off + 1];
    off += 2;
    if ((size_t)ext_total != msg_len - off) return -1;

    *ext_block     = msg + off;
    *ext_block_len = ext_total;
    return 0;
}

int quic_conn_initial_extract_client_hello(const quic_conn_t* c,
                                           tls13_client_hello_t* parsed_out,
                                           quic_transport_params_t* peer_tp_out)
{
    if (!c || !parsed_out || !peer_tp_out) return -1;

    size_t buf_len = 0;
    const uint8_t* buf = quic_crypto_rx_peek(&c->rx_initial, &buf_len);
    if (buf == NULL || buf_len < 4) return 0;

    /* Handshake header: type(1) + length(u24). RFC 8446 §4. */
    if (buf[0] != 0x01) return -1;                  /* must be client_hello */
    uint32_t hs_body_len = ((uint32_t)buf[1] << 16) |
                           ((uint32_t)buf[2] << 8)  |
                            (uint32_t)buf[3];
    size_t need = (size_t)hs_body_len + 4;
    if (buf_len < need) return 0;                   /* not enough yet */

    if (tls13_parse_client_hello(buf, need, parsed_out) != 0) return -1;

    const uint8_t* ext_block = NULL;
    size_t         ext_block_len = 0;
    if (locate_ch_extensions_block(buf, need, &ext_block, &ext_block_len) != 0)
        return -1;

    const uint8_t* tp_body = NULL;
    size_t         tp_body_len = 0;
    int rc = quic_tls_ext_find_tp(ext_block, ext_block_len,
                                  &tp_body, &tp_body_len);
    if (rc != 1) return -1;                         /* missing or malformed */

    if (quic_tp_decode(tp_body, tp_body_len, peer_tp_out) != 1) return -1;

    return 1;
}

/* ---- phase 5e3: outbound Initial emission ---------------------------- */

void quic_conn_set_our_scid(quic_conn_t* c,
                            const uint8_t* scid, size_t scid_len)
{
    if (!c) return;
    if (scid_len > QUIC_MAX_CID_LEN) scid_len = QUIC_MAX_CID_LEN;
    if (scid_len > 0 && scid != NULL) memcpy(c->our_scid, scid, scid_len);
    c->our_scid_len = scid_len;
}

void quic_conn_initial_tx_set_pending(quic_conn_t* c,
                                      const uint8_t* bytes, size_t len)
{
    if (!c) return;
    quic_crypto_tx_set_pending(&c->tx_initial, bytes, len);
}

/* Lazily derive the server-direction Initial keys (used for outbound
 * encryption). For a server conn that's is_server=1; for a client
 * conn it'd be is_server=0. The seed is peer_dcid — the very same DCID
 * the peer used to address its first Initial to us. */
static void ensure_initial_tx_keys(quic_conn_t* c)
{
    if (c->initial_tx_keys_ready) return;
    if (!c->peer_addrs_known) return;
    int is_server_for_encrypt = (c->role == QUIC_ROLE_SERVER) ? 1 : 0;
    quic_initial_derive(c->peer_dcid, c->peer_dcid_len,
                        is_server_for_encrypt, &c->initial_tx_keys);
    c->initial_tx_keys_ready = 1;
}

size_t quic_conn_emit_initial(quic_conn_t* c, uint8_t* out, size_t out_cap)
{
    if (!c || !out) return 0;
    if (!c->peer_addrs_known) return 0;

    /* Budget the CRYPTO chunk so the resulting packet fits in out_cap.
     * AEAD overhead = 16 bytes. Long header: 1 + 4 + 1 + dcid + 1 +
     * scid + 0 (token len, server) + 2 (length varint, conservative) +
     * pn_len. We use pn_len=2. CRYPTO frame overhead: 1 (type) + up to
     * 8 (offset varint) + up to 8 (length varint).
     *
     * To stay simple+correct we conservatively cap headers+overhead
     * and let the chunk fill the rest.
     */
    const size_t aead_tag = 16;
    const size_t hdr_overhead = 1 + 4 + 1 + c->peer_scid_len
                                + 1 + c->our_scid_len
                                + 1 /* token_len varint = 0 */
                                + 2 /* length varint */
                                + 2 /* pn_len */;
    const size_t crypto_frame_overhead = 1 /* type */ + 8 /* offset */ + 8 /* length */;
    const size_t fixed = hdr_overhead + crypto_frame_overhead + aead_tag;
    if (out_cap <= fixed) return 0;
    size_t chunk_budget = out_cap - fixed;

    uint64_t       chunk_off = 0;
    const uint8_t* chunk_ptr = NULL;
    size_t         chunk_len = 0;
    if (quic_crypto_tx_next(&c->tx_initial, chunk_budget,
                            &chunk_off, &chunk_ptr, &chunk_len) != 1) {
        return 0;  /* nothing pending */
    }

    /* Encode CRYPTO frame into a scratch payload buffer. */
    uint8_t frames[2048];
    if (chunk_len + 32 > sizeof frames) chunk_len = sizeof frames - 32;
    size_t fn = quic_frame_crypto_encode(frames, sizeof frames,
                                         chunk_off, chunk_ptr, chunk_len);
    if (fn == 0) return 0;

    ensure_initial_tx_keys(c);
    if (!c->initial_tx_keys_ready) return 0;

    quic_initial_pkt_t pkt = {0};
    pkt.version = 0x00000001u;
    if (c->peer_scid_len > 0)
        memcpy(pkt.dcid, c->peer_scid, c->peer_scid_len);
    pkt.dcid_len = c->peer_scid_len;
    if (c->our_scid_len > 0)
        memcpy(pkt.scid, c->our_scid, c->our_scid_len);
    pkt.scid_len = c->our_scid_len;
    pkt.token_len = 0;
    pkt.pn = c->initial_tx_next_pn;
    pkt.pn_len = 2;
    pkt.payload = frames;
    pkt.payload_len = fn;

    size_t n = quic_initial_build(out, out_cap, &pkt,
                                  &c->initial_tx_keys, /*pad_to_min=*/0);
    if (n == 0) return 0;

    quic_crypto_tx_consume(&c->tx_initial, chunk_len);
    c->initial_tx_next_pn++;
    return n;
}

/* ---- phase 5e5: Handshake-epoch tx + rx ---------------------------- */

static int hs_keys_install_one(const uint8_t* secret, size_t secret_len,
                               quic_handshake_keys_t* out)
{
    quic_keys_t big;
    if (!quic_keys_from_secret(secret, secret_len, 16, 16, &big)) return -1;
    /* Project quic_keys_t (variable-len storage) into the
     * fixed-size handshake_keys_t (= initial_keys_t = AES-128). */
    memcpy(out->key, big.key, 16);
    memcpy(out->iv,  big.iv,  12);
    memcpy(out->hp,  big.hp,  16);
    return 0;
}

int quic_conn_install_handshake_secrets(quic_conn_t* c,
                                        const uint8_t* tx_secret,
                                        const uint8_t* rx_secret,
                                        size_t secret_len)
{
    if (!c || !tx_secret || !rx_secret) return -1;
    if (c->handshake_keys_ready) return 0;
    quic_handshake_keys_t k_tx, k_rx;
    if (hs_keys_install_one(tx_secret, secret_len, &k_tx) != 0) return -1;
    if (hs_keys_install_one(rx_secret, secret_len, &k_rx) != 0) return -1;
    c->handshake_tx_keys = k_tx;
    c->handshake_rx_keys = k_rx;
    c->handshake_keys_ready = 1;
    return 0;
}

void quic_conn_handshake_tx_set_pending(quic_conn_t* c,
                                        const uint8_t* bytes, size_t len)
{
    if (!c) return;
    quic_crypto_tx_set_pending(&c->tx_handshake, bytes, len);
}

static int frame_allowed_in_handshake(uint8_t t)
{
    switch (t) {
    case QUIC_FT_PADDING:
    case QUIC_FT_PING:
    case QUIC_FT_ACK:
    case QUIC_FT_ACK_ECN:
    case QUIC_FT_CRYPTO:
    case QUIC_FT_CONNECTION_CLOSE:
        return 1;
    default:
        return 0;
    }
}

int quic_conn_recv_handshake(quic_conn_t* c,
                             const uint8_t* datagram, size_t len)
{
    if (!c || !datagram) return -1;
    if (!c->handshake_keys_ready) return -1;
    if (len < 7) return -1;
    /* Long header + fixed bit set; type bits = 10 (Handshake). */
    if ((datagram[0] & 0xc0) != 0xc0) return -1;
    if ((datagram[0] & 0x30) != 0x20) return -1;
    uint32_t version = ((uint32_t)datagram[1] << 24) |
                       ((uint32_t)datagram[2] << 16) |
                       ((uint32_t)datagram[3] << 8)  |
                        (uint32_t)datagram[4];
    if (version != 0x00000001u) return -1;

    quic_handshake_pkt_t pkt;
    uint8_t scratch[2048];
    if (quic_handshake_parse(datagram, len, &c->handshake_rx_keys,
                             &pkt, scratch, sizeof scratch) != 0) {
        return -1;
    }
    c->handshake_pkts_rcvd++;

    size_t fo = 0;
    while (fo < pkt.payload_len) {
        quic_frame_t f;
        size_t consumed = quic_frame_decode(pkt.payload + fo,
                                            pkt.payload_len - fo, &f);
        if (consumed == 0) break;
        if (consumed == QUIC_FRAME_DECODE_ERROR) return -1;
        fo += consumed;

        if (!frame_allowed_in_handshake(f.type)) return -1;

        switch (f.type) {
        case QUIC_FT_CRYPTO: {
            int rc = quic_crypto_rx_stage(&c->rx_handshake,
                                          f.u.crypto.offset,
                                          f.u.crypto.data,
                                          (size_t)f.u.crypto.length);
            if (rc < 0) return -1;
            c->handshake_crypto_bytes_rcvd += f.u.crypto.length;
            c->handshake_ack_eliciting_rcvd++;
            break;
        }
        case QUIC_FT_PING:
            c->handshake_ack_eliciting_rcvd++;
            break;
        case QUIC_FT_ACK:
        case QUIC_FT_ACK_ECN:
        case QUIC_FT_PADDING:
        case QUIC_FT_CONNECTION_CLOSE:
            break;
        default:
            return -1;
        }
    }
    return 0;
}

const uint8_t* quic_conn_handshake_rx_peek(const quic_conn_t* c, size_t* out_len)
{
    return quic_crypto_rx_peek(&c->rx_handshake, out_len);
}

void quic_conn_handshake_rx_advance(quic_conn_t* c, size_t n)
{
    quic_crypto_rx_advance(&c->rx_handshake, n);
}

size_t quic_conn_emit_handshake(quic_conn_t* c, uint8_t* out, size_t out_cap)
{
    if (!c || !out) return 0;
    if (!c->peer_addrs_known) return 0;
    if (!c->handshake_keys_ready) return 0;

    /* Same overhead model as Initial except no token_len byte. */
    const size_t aead_tag = 16;
    const size_t hdr_overhead = 1 + 4 + 1 + c->peer_scid_len
                                + 1 + c->our_scid_len
                                + 2 /* length varint */
                                + 2 /* pn_len */;
    const size_t crypto_frame_overhead = 1 + 8 + 8;
    const size_t fixed = hdr_overhead + crypto_frame_overhead + aead_tag;
    if (out_cap <= fixed) return 0;
    size_t chunk_budget = out_cap - fixed;

    uint64_t       chunk_off = 0;
    const uint8_t* chunk_ptr = NULL;
    size_t         chunk_len = 0;
    if (quic_crypto_tx_next(&c->tx_handshake, chunk_budget,
                            &chunk_off, &chunk_ptr, &chunk_len) != 1) {
        return 0;
    }

    uint8_t frames[2048];
    if (chunk_len + 32 > sizeof frames) chunk_len = sizeof frames - 32;
    size_t fn = quic_frame_crypto_encode(frames, sizeof frames,
                                         chunk_off, chunk_ptr, chunk_len);
    if (fn == 0) return 0;

    quic_handshake_pkt_t pkt = {0};
    pkt.version = 0x00000001u;
    if (c->peer_scid_len > 0)
        memcpy(pkt.dcid, c->peer_scid, c->peer_scid_len);
    pkt.dcid_len = c->peer_scid_len;
    if (c->our_scid_len > 0)
        memcpy(pkt.scid, c->our_scid, c->our_scid_len);
    pkt.scid_len = c->our_scid_len;
    pkt.pn = c->handshake_tx_next_pn;
    pkt.pn_len = 2;
    pkt.payload = frames;
    pkt.payload_len = fn;

    size_t n = quic_handshake_build(out, out_cap, &pkt,
                                    &c->handshake_tx_keys);
    if (n == 0) return 0;

    quic_crypto_tx_consume(&c->tx_handshake, chunk_len);
    c->handshake_tx_next_pn++;
    return n;
}

/* ---- phase 5e7: client Finished verify + 1-RTT key install -------- */

#include "../tls/handshake.h"
#include "../tls/keysched.h"

int quic_server_finish_handshake(quic_conn_t* c)
{
    if (!c) return -1;
    if (!c->have_handshake_state) return -1;
    if (c->app_keys_ready) return 0;

    /* Peek the buffered client Finished. RFC 8446 §4.4.4: 0x14 then
     * u24 length; verify_data is 32 bytes for SHA-256 suites. */
    size_t avail = 0;
    const uint8_t* fin = quic_crypto_rx_peek(&c->rx_handshake, &avail);
    if (!fin || avail < 4) return -1;
    if (fin[0] != 0x14) return -1;
    uint32_t body_len = ((uint32_t)fin[1] << 16) |
                        ((uint32_t)fin[2] <<  8) |
                         (uint32_t)fin[3];
    if (body_len != 32) return -1;
    if (avail < 4 + 32) return -1;

    /* Verify the client Finished against the SH-flight transcript
     * (== transcript_hash_thru_server_fin). */
    if (tls13_verify_finished(c->client_handshake_traffic_secret,
                              c->transcript_hash_thru_server_fin,
                              fin + 4) != 0) {
        return -1;
    }

    /* Derive application secrets. Note: per RFC 8446 §7.1, c_ap and
     * s_ap are derived from the SAME transcript snapshot used for the
     * server Finished — the client Finished is verified against that
     * same snapshot but does NOT itself feed into c_ap/s_ap. */
    uint8_t ms[32], c_ap[32], s_ap[32];
    if (tls13_compute_application_secrets(c->handshake_secret,
                                          c->transcript_hash_thru_server_fin,
                                          ms, c_ap, s_ap) != 0) return -1;

    /* Derive AES-128-GCM 1-RTT packet keys. Reuse the local helper
     * pattern from hs_keys_install_one. */
    quic_keys_t big_tx, big_rx;
    if (!quic_keys_from_secret(s_ap, 32, 16, 16, &big_tx)) return -1;
    if (!quic_keys_from_secret(c_ap, 32, 16, 16, &big_rx)) return -1;

    memcpy(c->app_tx_keys.key, big_tx.key, 16);
    memcpy(c->app_tx_keys.iv,  big_tx.iv,  12);
    memcpy(c->app_tx_keys.hp,  big_tx.hp,  16);
    memcpy(c->app_rx_keys.key, big_rx.key, 16);
    memcpy(c->app_rx_keys.iv,  big_rx.iv,  12);
    memcpy(c->app_rx_keys.hp,  big_rx.hp,  16);

    memcpy(c->client_application_traffic_secret_0, c_ap, 32);
    memcpy(c->server_application_traffic_secret_0, s_ap, 32);
    memcpy(c->master_secret, ms, 32);
    c->app_keys_ready = 1;

    /* Consume the Finished bytes from the Handshake-epoch reassembler. */
    quic_crypto_rx_advance(&c->rx_handshake, 4 + 32);
    return 0;
}

/* ---- phase 6a: 1-RTT short-header tx + rx --------------------------- */

uint64_t quic_conn_app_tx_next_pn(const quic_conn_t* c)
{
    return c ? c->app_tx_next_pn : 0;
}

size_t quic_conn_emit_app(quic_conn_t* c,
                          const uint8_t* payload, size_t payload_len,
                          uint8_t* out, size_t out_cap)
{
    if (!c || !out || (!payload && payload_len > 0)) return 0;
    if (!c->app_keys_ready) return 0;
    if (!c->peer_addrs_known) return 0;

    /* Header overhead: byte0(1) + dcid + pn(2) + tag(16). */
    const size_t hdr = 1 + c->peer_scid_len + 2 + 16u;
    if (out_cap < hdr + payload_len) return 0;

    quic_short_pkt_t pkt = {0};
    if (c->peer_scid_len > sizeof pkt.dcid) return 0;
    memcpy(pkt.dcid, c->peer_scid, c->peer_scid_len);
    pkt.dcid_len    = c->peer_scid_len;
    pkt.pn          = c->app_tx_next_pn;
    pkt.pn_len      = 2;
    pkt.payload     = payload;
    pkt.payload_len = payload_len;

    size_t n = quic_short_build(out, out_cap, &pkt, &c->app_tx_keys);
    if (n == 0) return 0;
    c->app_tx_next_pn++;
    return n;
}

int quic_conn_recv_app(quic_conn_t* c, const uint8_t* datagram, size_t len)
{
    if (!c || !datagram) return -1;
    if (!c->app_keys_ready) return -1;
    if (len < 1) return -1;
    /* form bit must be clear (short header), fixed bit must be set. */
    if ((datagram[0] & 0x80) != 0) return -1;
    if ((datagram[0] & 0x40) == 0) return -1;

    quic_short_pkt_t pkt;
    uint8_t scratch[2048];
    if (quic_short_parse(datagram, len, c->our_scid_len,
                         &c->app_rx_keys,
                         &pkt, scratch, sizeof scratch) != 0) {
        return -1;
    }
    /* DCID match check. */
    if (pkt.dcid_len != c->our_scid_len ||
        memcmp(pkt.dcid, c->our_scid, c->our_scid_len) != 0) {
        return -1;
    }
    c->app_pkts_rcvd++;

    /* Frame walk — for the spike we accept PADDING/PING/ACK and
     * STREAM-class frames (0x08..0x0f) without further processing.
     * Real frame handling lands in subsequent phases. */
    size_t fo = 0;
    while (fo < pkt.payload_len) {
        quic_frame_t f;
        size_t consumed = quic_frame_decode(pkt.payload + fo,
                                            pkt.payload_len - fo, &f);
        if (consumed == 0) break;
        if (consumed == QUIC_FRAME_DECODE_ERROR) return -1;
        fo += consumed;
        /* All frames currently accepted; no per-type rejection in this
         * phase (RFC 9000 §12.4 enforcement comes in 6b). */
    }
    return 0;
}
