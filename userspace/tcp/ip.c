/*
 * IPv4 + TCP header build/parse (RFC 791 / RFC 9293).
 */

#include "ip.h"

#include <string.h>

/* RFC 1071 internet checksum: 16-bit one's complement sum, with
 * end-around carry, then bitwise NOT. */
uint16_t inet_csum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    while (len >= 2) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len  -= 2;
    }
    if (len) sum += (uint32_t)data[0] << 8;     /* pad odd byte */
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

/* Pseudo-header followed by the TCP header + payload, all zero-
 * padded to even length. We compute on the fly without an extra
 * buffer to keep this allocation-free. */
uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const uint8_t* tcp, size_t tcp_len) {
    uint32_t sum = 0;

    /* Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + len(2) */
    sum += (src_ip >> 16) & 0xffff;
    sum += (src_ip >>  0) & 0xffff;
    sum += (dst_ip >> 16) & 0xffff;
    sum += (dst_ip >>  0) & 0xffff;
    sum += IPPROTO_TCP_VAL;
    sum += (uint32_t)tcp_len;

    /* TCP header + payload. The on-wire checksum field is at
     * tcp+16; treat it as zero while summing. */
    for (size_t i = 0; i + 1 < tcp_len; i += 2) {
        if (i == 16) continue;          /* skip checksum field */
        sum += ((uint32_t)tcp[i] << 8) | tcp[i + 1];
    }
    if (tcp_len & 1) sum += (uint32_t)tcp[tcp_len - 1] << 8;

    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

static uint16_t rd16(const uint8_t* p) { return ((uint16_t)p[0] << 8) | p[1]; }
static uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static void wr16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void wr32(uint8_t* p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

int ip_tcp_parse(const uint8_t* frame, size_t len, tcp_seg_t* out) {
    if (len < IPV4_HEADER_LEN) return -1;
    if ((frame[0] >> 4) != 4) return -1;            /* not IPv4 */
    size_t ihl = (frame[0] & 0x0f) * 4u;
    if (ihl < IPV4_HEADER_LEN || ihl > len) return -1;
    if (frame[9] != IPPROTO_TCP_VAL) return -1;
    uint16_t total = rd16(frame + 2);
    if (total > len) return -1;

    /* IPv4 header checksum check (RFC 791). */
    if (inet_csum(frame, ihl) != 0) return -1;

    out->src_ip = rd32(frame + 12);
    out->dst_ip = rd32(frame + 16);

    const uint8_t* tcp = frame + ihl;
    size_t tcp_len = total - ihl;
    if (tcp_len < TCP_HEADER_LEN) return -1;
    /* Belt-and-braces buffer-bounds check: total <= len was already
     * enforced above, but make the post-condition explicit so future
     * edits to the header walk can't sneak past it. */
    if ((size_t)(tcp - frame) + tcp_len > len) return -1;
    size_t doff = ((tcp[12] >> 4) & 0x0f) * 4u;
    if (doff < TCP_HEADER_LEN || doff > tcp_len) return -1;

    /* TCP checksum. */
    if (tcp_checksum(out->src_ip, out->dst_ip, tcp, tcp_len) !=
        rd16(tcp + 16)) return -1;

    out->src_port = rd16(tcp + 0);
    out->dst_port = rd16(tcp + 2);
    out->seq      = rd32(tcp + 4);
    out->ack      = rd32(tcp + 8);
    out->flags    = tcp[13];
    out->window   = rd16(tcp + 14);
    out->payload  = tcp + doff;
    out->payload_len = tcp_len - doff;
    return 0;
}

size_t ip_tcp_build(uint8_t* out, size_t out_cap, const tcp_seg_t* seg) {
    size_t total = IPV4_HEADER_LEN + TCP_HEADER_LEN + seg->payload_len;
    if (total > out_cap || total > 0xffff) return 0;

    /* IPv4 header. */
    out[0] = 0x45;                 /* version=4, ihl=5 */
    out[1] = 0;                    /* DSCP/ECN */
    wr16(out + 2, (uint16_t)total);
    wr16(out + 4, 0);              /* identification (no fragmentation) */
    wr16(out + 6, 0x4000);         /* DF set, fragment offset 0 */
    out[8] = 64;                   /* TTL */
    out[9] = IPPROTO_TCP_VAL;
    wr16(out + 10, 0);             /* checksum (filled in below) */
    wr32(out + 12, seg->src_ip);
    wr32(out + 16, seg->dst_ip);
    uint16_t ip_csum = inet_csum(out, IPV4_HEADER_LEN);
    wr16(out + 10, ip_csum);

    /* TCP header. */
    uint8_t* tcp = out + IPV4_HEADER_LEN;
    wr16(tcp + 0, seg->src_port);
    wr16(tcp + 2, seg->dst_port);
    wr32(tcp + 4, seg->seq);
    wr32(tcp + 8, seg->ack);
    tcp[12] = (TCP_HEADER_LEN / 4u) << 4;       /* data offset */
    tcp[13] = seg->flags;
    wr16(tcp + 14, seg->window);
    wr16(tcp + 16, 0);                          /* checksum placeholder */
    wr16(tcp + 18, 0);                          /* urgent pointer */
    if (seg->payload_len) {
        memcpy(tcp + TCP_HEADER_LEN, seg->payload, seg->payload_len);
    }
    uint16_t csum = tcp_checksum(seg->src_ip, seg->dst_ip,
                                 tcp, TCP_HEADER_LEN + seg->payload_len);
    wr16(tcp + 16, csum);
    return total;
}
