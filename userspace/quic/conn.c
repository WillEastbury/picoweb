#include "conn.h"
#include "frames.h"
#include "tls_ext.h"

#include <string.h>

void quic_conn_init_server(quic_conn_t* c)
{
    memset(c, 0, sizeof(*c));
    c->role = QUIC_ROLE_SERVER;
    quic_crypto_rx_init(&c->rx_initial,
                        c->rx_initial_data, sizeof c->rx_initial_data,
                        c->rx_initial_bm,   sizeof c->rx_initial_bm);
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
