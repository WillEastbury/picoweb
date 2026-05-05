/*
 * IPv4 + TCP header build/parse helpers (RFC 791 / RFC 9293).
 *
 * Spike-grade. No options, no fragmentation, no IP routing. Fixed
 * 20-byte IPv4 header + fixed 20-byte TCP header. The userspace
 * stack only needs to:
 *
 *   - parse one inbound IPv4 datagram off AF_PACKET
 *   - validate IPv4 + TCP checksums
 *   - hand the TCP segment off to tcp.c
 *   - build outbound IPv4+TCP datagrams with correct checksums
 *
 * IPv6 is out of scope.
 */
#ifndef PICOWEB_USERSPACE_TCP_IP_H
#define PICOWEB_USERSPACE_TCP_IP_H

#include <stddef.h>
#include <stdint.h>

#define IPV4_HEADER_LEN 20u
#define TCP_HEADER_LEN  20u

#define IPPROTO_TCP_VAL 6u

/* TCP flag bits (RFC 9293 §3.1). */
#define TCPF_FIN  0x01u
#define TCPF_SYN  0x02u
#define TCPF_RST  0x04u
#define TCPF_PSH  0x08u
#define TCPF_ACK  0x10u
#define TCPF_URG  0x20u

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint8_t  flags;
    const uint8_t* payload;
    size_t   payload_len;
} tcp_seg_t;

/* Internet checksum (RFC 1071). One's-complement sum of 16-bit
 * words. Caller passes the buffer and length (bytes). */
uint16_t inet_csum(const uint8_t* data, size_t len);

/* TCP checksum requires a pseudo-header (src_ip, dst_ip, zero,
 * proto=6, tcp_length). This helper computes the full checksum
 * over (pseudo_header || tcp_header || tcp_payload). */
uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const uint8_t* tcp, size_t tcp_len);

/* Parse an inbound Ethernet+IPv4+TCP frame. `frame` points at the
 * IPv4 header (Ethernet header already stripped by the caller).
 * Returns 0 on success, -1 on malformed / wrong proto / bad csum. */
int ip_tcp_parse(const uint8_t* frame, size_t len, tcp_seg_t* out);

/* Build an outbound IPv4+TCP datagram into `out`. Returns total
 * length written, or 0 on overflow. The caller is responsible for
 * prepending the Ethernet header. */
size_t ip_tcp_build(uint8_t* out, size_t out_cap, const tcp_seg_t* seg);

#endif
