/*
 * IPv4 + UDP header build/parse helpers (RFC 768 / RFC 791).
 *
 * Spike-grade. No IP options, no fragmentation. Fixed 20-byte
 * IPv4 header + fixed 8-byte UDP header. Used by the QUIC
 * transport (RFC 9000) to ship UDP datagrams over the existing
 * AF_XDP raw-IP path. No socket() involvement.
 *
 * IPv6 is out of scope.
 */
#ifndef PICOWEB_USERSPACE_UDP_UDP_H
#define PICOWEB_USERSPACE_UDP_UDP_H

#include <stddef.h>
#include <stdint.h>

#define UDP_HEADER_LEN  8u
#define IPPROTO_UDP_VAL 17u

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t* payload;
    size_t   payload_len;
} udp_dgram_t;

/* UDP checksum over (pseudo_header || udp_header || udp_payload).
 * Computed identically to TCP's pseudo-header per RFC 768. A return
 * value of 0xffff indicates "no checksum" should never be emitted by
 * us; we always send the real checksum. */
uint16_t udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const uint8_t* udp, size_t udp_len);

/* Parse an inbound IPv4+UDP datagram. `frame` points at the IPv4
 * header (Ethernet header already stripped by the caller). Returns
 * 0 on success, -1 on malformed / wrong proto / bad csum.
 *
 * If the inbound datagram has UDP checksum field == 0 (legal per
 * RFC 768 for IPv4) the checksum is accepted without verification.
 */
int ip_udp_parse(const uint8_t* frame, size_t len, udp_dgram_t* out);

/* Extended parse: `skip_csum` non-zero skips UDP checksum
 * verification (e.g. when NIC offload is unreliable / loopback). */
int ip_udp_parse_ex(const uint8_t* frame, size_t len, udp_dgram_t* out,
                    int skip_csum);

/* Build an outbound IPv4+UDP datagram into `out`. Returns total
 * bytes written (IPv4+UDP+payload), or 0 on overflow. The caller
 * is responsible for prepending the Ethernet header (af_xdp does
 * this). The UDP checksum is always populated. */
size_t ip_udp_build(uint8_t* out, size_t out_cap, const udp_dgram_t* seg);

#endif
