/*
 * Per-connection run-to-completion runtime — see conn.h for the
 * architectural rationale.
 *
 * The pipeline inside `pw_conn_rx`:
 *
 *   1) Append the new bytes to rx_buf, growing rx_len.
 *
 *   2) Inspect the first 5 bytes (TLS record header) to learn the
 *      ciphertext length. If we don't yet have the full record's
 *      worth of bytes, return NEED_MORE — the caller will feed us
 *      more bytes when TCP delivers them.
 *
 *   3) AEAD-open the record in place. If the tag is wrong, return
 *      AUTH_FAIL and abandon the buffer (caller closes the conn).
 *
 *   4) Hand the recovered inner plaintext to response_fn. The
 *      callee produces a `pw_response_t` of fragment descriptors.
 *
 *   5) Seal one outbound record over the response fragments via
 *      `tls13_seal_record_iov`. The sealed bytes are written to
 *      `out` and `*out_len` is set.
 *
 *   6) Reset rx_buf for the next request (HTTP/1.1 single-shot;
 *      pipelining is handled by re-entry from the caller).
 *
 * No allocation. All paths are deterministic.
 */

#include "conn.h"

#include <string.h>

#include "crypto/util.h"

void pw_conn_init(pw_conn_t* c,
                  const tls_record_dir_t* rx_dir,
                  const tls_record_dir_t* tx_dir) {
    memset(c, 0, sizeof(*c));
    c->rx = *rx_dir;
    c->tx = *tx_dir;
}

pw_conn_status_t pw_conn_rx(pw_conn_t* c,
                            const uint8_t* in, size_t in_len,
                            pw_response_fn response_fn, void* response_user,
                            uint8_t* out, size_t out_cap, size_t* out_len) {
    if (out_len) *out_len = 0;

    /* 1) Append. Bound the rx buffer; oversize records are a
     *    protocol error (record exceeds 2^14 + slop). */
    if (c->rx_len + in_len > sizeof(c->rx_buf)) {
        return PW_CONN_PROTOCOL_ERR;
    }
    if (in_len) memcpy(c->rx_buf + c->rx_len, in, in_len);
    c->rx_len += in_len;
    c->bytes_in += in_len;

    /* 2) Need at least a record header to know the cipher_len. */
    if (c->rx_len < TLS13_RECORD_HEADER_LEN) return PW_CONN_NEED_MORE;
    size_t cipher_len = ((size_t)c->rx_buf[3] << 8) | c->rx_buf[4];
    /* RFC 8446 §5.2: ciphertext length must fit in u16 and be
     * <= TLSCiphertext.length cap. */
    if (cipher_len > TLS13_MAX_CIPHERTEXT) return PW_CONN_PROTOCOL_ERR;
    size_t record_len = TLS13_RECORD_HEADER_LEN + cipher_len;
    if (c->rx_len < record_len) return PW_CONN_NEED_MORE;

    /* 3) Decrypt in place. */
    tls_content_type_t inner = TLS_CT_INVALID;
    uint8_t* pt_in = NULL;
    size_t   pt_in_len = 0;
    int orc = tls13_open_record(&c->rx, c->rx_buf, record_len,
                                &inner, &pt_in, &pt_in_len);
    if (orc != 0) return PW_CONN_AUTH_FAIL;
    if (inner != TLS_CT_APPLICATION_DATA) {
        /* Spike: only application_data on this path. Handshake /
         * alert / change_cipher_spec records would be steered to a
         * separate handler in a real implementation. */
        return PW_CONN_PROTOCOL_ERR;
    }
    c->records_in++;

    /* Copy the recovered plaintext out of rx_buf into pt_buf so that
     * (a) the response_fn sees a stable input slice that doesn't
     * mutate when we reset rx_buf, and (b) the rx_buf is freed up
     * for the next inbound record before we do any sealing work. */
    if (pt_in_len > sizeof(c->pt_buf)) return PW_CONN_PROTOCOL_ERR;
    if (pt_in_len) memcpy(c->pt_buf, pt_in, pt_in_len);
    size_t request_len = pt_in_len;

    /* Reset rx_buf for the next record. (A future iteration could
     * memmove any tail bytes belonging to a pipelined record — but
     * HTTP/1.1 pipelining is rare in practice and we'd rather have
     * the simpler invariant for now.) */
    secure_zero(c->rx_buf, c->rx_len);
    c->rx_len = 0;

    /* 4) Webserver-as-module: fill response. */
    pw_response_t resp = {0};
    int rrc = response_fn(c->pt_buf, request_len, &resp, response_user);
    if (rrc != 0)               return PW_CONN_RESPONSE_FAIL;
    if (resp.n > PW_IOV_MAX_FRAGS) return PW_CONN_RESPONSE_FAIL;

    /* Recompute total_len defensively — the response_fn may have set
     * it but we don't trust the input. */
    size_t total = 0;
    for (unsigned i = 0; i < resp.n; i++) total += resp.parts[i].len;
    if (total > TLS13_MAX_PLAINTEXT) return PW_CONN_RESPONSE_FAIL;

    /* 5) Seal one outbound record straight from the iov chain. The
     * total length is known up front so the record header is written
     * before any encrypt work happens — exactly the property we want
     * from the iov path. */
    if (out_cap < TLS13_RECORD_HEADER_LEN + total + TLS13_AEAD_TAG_LEN + 1) {
        return PW_CONN_OUT_OVERFLOW;
    }
    size_t sealed = tls13_seal_record_iov(&c->tx,
                                          TLS_CT_APPLICATION_DATA,
                                          TLS_CT_APPLICATION_DATA,
                                          resp.parts, resp.n, total,
                                          out, out_cap);
    if (sealed == 0) return PW_CONN_OUT_OVERFLOW;

    /* Wipe the plaintext request buffer — no secrets should linger
     * across requests on the same connection. */
    if (request_len) secure_zero(c->pt_buf, request_len);

    if (out_len) *out_len = sealed;
    c->bytes_out += sealed;
    c->records_out++;
    return PW_CONN_OK;
}
