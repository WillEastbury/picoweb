/*
 * AF_PACKET RX/TX skeleton (Linux raw L2 sockets).
 *
 * This is the I/O backend for the userspace TCP+TLS spike when run
 * against a real Linux box (NOT WSL, where there is no NIC to bind
 * to). Even on Linux this is far slower than DPDK or AF_XDP because
 * every frame still traverses the kernel networking copy path —
 * we're only avoiding the kernel TCP stack, not the kernel itself.
 *
 * For zero-copy RX/TX you'd want PACKET_MMAP rings or AF_XDP. That
 * is sketched in dpdk_sketch.c.
 */
#ifndef PICOWEB_USERSPACE_IO_AF_PACKET_H
#define PICOWEB_USERSPACE_IO_AF_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define ETH_HDR_LEN 14u
#define ETH_TYPE_IPV4 0x0800u

typedef struct {
    int     fd;
    int     ifindex;
    uint8_t local_mac[6];
    uint8_t peer_mac[6];      /* learned via static config in spike */
} af_packet_t;

/* Open AF_PACKET socket bound to the given interface. */
int af_packet_open(af_packet_t* a, const char* ifname,
                   const uint8_t local_mac[6],
                   const uint8_t peer_mac[6]);

/* Install a classic-BPF filter that accepts only IPv4 TCP frames whose
 * IP destination equals local_ip (network byte order) and whose TCP
 * destination port equals dst_port (host byte order). All other
 * frames are dropped in-kernel before reaching userspace. Also
 * disables PACKET_IGNORE_OUTGOING reflection so we don't RX our own
 * transmits. Returns 0 on success, -1 on error. Safe to call once
 * after open(). */
int af_packet_install_filter(af_packet_t* a,
                             uint32_t local_ip_be,
                             uint16_t dst_port_host);

/* Receive next frame; returns L3 (IPv4) start pointer + length, or
 * -1 on error / non-IPv4 frame. The caller's buffer must be at
 * least 1518 bytes. *csum_not_ready is set to 1 when the kernel
 * flags TP_STATUS_CSUMNOTREADY (TX offload left checksum
 * incomplete — caller should skip verification). */
int af_packet_recv(af_packet_t* a,
                   uint8_t* buf, size_t buf_cap,
                   const uint8_t** ip_out, size_t* ip_len_out,
                   int* csum_not_ready);

/* Send one IPv4 frame: prepends Ethernet header. */
int af_packet_send_ipv4(af_packet_t* a,
                        const uint8_t* ip, size_t ip_len);

void af_packet_close(af_packet_t* a);

#endif
