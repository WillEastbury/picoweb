#include "tls_ext.h"

#include <string.h>

size_t quic_tls_ext_emit_tp(uint8_t* out, size_t out_cap,
                            const uint8_t* tp_blob, size_t tp_blob_len)
{
    if (tp_blob_len > 0xffffu) return 0;
    if (out_cap < 4u + tp_blob_len) return 0;
    if (tp_blob_len && tp_blob == NULL) return 0;

    out[0] = (uint8_t)(QUIC_TLS_EXT_TRANSPORT_PARAMETERS >> 8);
    out[1] = (uint8_t)(QUIC_TLS_EXT_TRANSPORT_PARAMETERS & 0xff);
    out[2] = (uint8_t)(tp_blob_len >> 8);
    out[3] = (uint8_t)(tp_blob_len & 0xff);
    if (tp_blob_len) memcpy(out + 4, tp_blob, tp_blob_len);
    return 4u + tp_blob_len;
}

int quic_tls_ext_find_tp(const uint8_t* ext_block, size_t ext_block_len,
                         const uint8_t** out_body, size_t* out_body_len)
{
    size_t off = 0;
    int    found = 0;
    const uint8_t* found_p = NULL;
    size_t         found_l = 0;

    while (off < ext_block_len) {
        if (ext_block_len - off < 4) return -1;
        uint16_t type = (uint16_t)((ext_block[off] << 8) | ext_block[off + 1]);
        uint16_t len  = (uint16_t)((ext_block[off + 2] << 8) | ext_block[off + 3]);
        off += 4;
        if (len > ext_block_len - off) return -1;

        if (type == QUIC_TLS_EXT_TRANSPORT_PARAMETERS) {
            if (found) return -1;  /* duplicate */
            found_p = ext_block + off;
            found_l = len;
            found = 1;
        }

        off += len;
    }

    if (!found) return 0;
    *out_body     = found_p;
    *out_body_len = found_l;
    return 1;
}
