/*
 * IPv4 + UDP build/parse (RFC 768 / RFC 791). Pseudo-header
 * checksum identical in form to TCP's. Modeled on userspace/tcp/ip.c.
 */

#include "udp.h"

#include "../tcp/ip.h"   /* inet_csum, IPV4_HEADER_LEN */

#include <string.h>

uint16_t udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const uint8_t* udp, size_t udp_len) {
    uint32_t sum = 0;

    /* Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + len(2) */
    sum += (src_ip >> 16) & 0xffff;
    sum += (src_ip >>  0) & 0xffff;
    sum += (dst_ip >> 16) & 0xffff;
    sum += (dst_ip >>  0) & 0xffff;
    sum += IPPROTO_UDP_VAL;
    sum += (uint32_t)udp_len;

    /* UDP header + payload. The on-wire checksum field is at
     * udp+6; treat it as zero while summing. */
    for (size_t i = 0; i + 1 < udp_len; i += 2) {
        if (i == 6) continue;       /* skip checksum field */
        sum += ((uint32_t)udp[i] << 8) | udp[i + 1];
    }
    if (udp_len & 1) sum += (uint32_t)udp[udp_len - 1] << 8;

    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t cs = (uint16_t)(~sum & 0xffff);
    /* RFC 768: the value 0x0000 means "no checksum"; if the real
     * computed value is zero, transmit it as 0xffff so the receiver
     * still validates. */
    return cs ? cs : 0xffffu;
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

int ip_udp_parse(const uint8_t* frame, size_t len, udp_dgram_t* out) {
    return ip_udp_parse_ex(frame, len, out, 0);
}

int ip_udp_parse_ex(const uint8_t* frame, size_t len, udp_dgram_t* out,
                    int skip_csum) {
    if (len < IPV4_HEADER_LEN) return -1;
    if ((frame[0] >> 4) != 4) return -1;            /* not IPv4 */
    size_t ihl = (frame[0] & 0x0f) * 4u;
    if (ihl < IPV4_HEADER_LEN || ihl > len) return -1;
    if (frame[9] != IPPROTO_UDP_VAL) return -1;
    uint16_t total = rd16(frame + 2);
    if (total > len) return -1;

    /* Always validate the IPv4 header checksum. */
    if (inet_csum(frame, ihl) != 0) return -1;

    out->src_ip = rd32(frame + 12);
    out->dst_ip = rd32(frame + 16);

    const uint8_t* udp = frame + ihl;
    if (total < ihl + UDP_HEADER_LEN) return -1;
    size_t udp_total = total - ihl;
    if ((size_t)(udp - frame) + udp_total > len) return -1;

    uint16_t udp_len_field = rd16(udp + 4);
    if (udp_len_field < UDP_HEADER_LEN) return -1;
    if (udp_len_field > udp_total) return -1;

    uint16_t wire_csum = rd16(udp + 6);
    if (!skip_csum && wire_csum != 0) {
        if (udp_checksum(out->src_ip, out->dst_ip, udp, udp_len_field)
            != wire_csum) return -1;
    }

    out->src_port = rd16(udp + 0);
    out->dst_port = rd16(udp + 2);
    out->payload  = udp + UDP_HEADER_LEN;
    out->payload_len = udp_len_field - UDP_HEADER_LEN;
    return 0;
}

size_t ip_udp_build(uint8_t* out, size_t out_cap, const udp_dgram_t* seg) {
    size_t udp_total = UDP_HEADER_LEN + seg->payload_len;
    size_t total     = IPV4_HEADER_LEN + udp_total;
    if (udp_total > 0xffff) return 0;
    if (total > out_cap || total > 0xffff) return 0;

    /* IPv4 header. */
    out[0] = 0x45;                 /* version=4, ihl=5 */
    out[1] = 0;
    wr16(out + 2, (uint16_t)total);
    wr16(out + 4, 0);              /* identification */
    wr16(out + 6, 0x4000);         /* DF set, fragment offset 0 */
    out[8] = 64;                   /* TTL */
    out[9] = IPPROTO_UDP_VAL;
    wr16(out + 10, 0);             /* checksum placeholder */
    wr32(out + 12, seg->src_ip);
    wr32(out + 16, seg->dst_ip);
    uint16_t ip_csum = inet_csum(out, IPV4_HEADER_LEN);
    wr16(out + 10, ip_csum);

    /* UDP header. */
    uint8_t* udp = out + IPV4_HEADER_LEN;
    wr16(udp + 0, seg->src_port);
    wr16(udp + 2, seg->dst_port);
    wr16(udp + 4, (uint16_t)udp_total);
    wr16(udp + 6, 0);                            /* csum placeholder */
    if (seg->payload_len) {
        memcpy(udp + UDP_HEADER_LEN, seg->payload, seg->payload_len);
    }
    uint16_t csum = udp_checksum(seg->src_ip, seg->dst_ip,
                                 udp, udp_total);
    wr16(udp + 6, csum);
    return total;
}
