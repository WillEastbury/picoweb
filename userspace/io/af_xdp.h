#ifndef PICOWEB_USERSPACE_IO_AF_XDP_H
#define PICOWEB_USERSPACE_IO_AF_XDP_H

#include <stddef.h>
#include <stdint.h>

#include <linux/if_xdp.h>

#include "af_packet.h" /* ETH_HDR_LEN / ETH_TYPE_IPV4 */

typedef struct {
    int fd;
    int ifindex;
    uint32_t queue_id;

    uint8_t local_mac[6];
    uint8_t peer_mac[6];

    void* umem;
    size_t umem_len;
    uint32_t frame_size;
    uint32_t frame_count;
    uint64_t tx_free[2048];
    uint32_t tx_free_n;

    struct {
        uint32_t* producer;
        uint32_t* consumer;
        uint32_t* flags;
        struct xdp_desc* desc;
        uint32_t mask;
    } rx, tx;
    struct {
        uint32_t* producer;
        uint32_t* consumer;
        uint32_t* flags;
        uint64_t* desc;
        uint32_t mask;
    } fr, cr;
    void* rx_map;
    void* tx_map;
    void* fr_map;
    void* cr_map;
    size_t rx_map_len, tx_map_len, fr_map_len, cr_map_len;
} af_xdp_t;

/* Open AF_XDP in copy-mode. Caller provides ifname, queue id, and
 * local/peer MAC addresses used for frame TX build.
 *
 * Requires kernel support for AF_XDP and CAP_NET_RAW/CAP_BPF-ish
 * privileges depending on host policy.
 */
int af_xdp_open(af_xdp_t* x, const char* ifname, uint32_t queue_id,
                const uint8_t local_mac[6], const uint8_t peer_mac[6]);

/* Receive one frame into caller-provided `buf`. On success sets ip_out
 * to the IPv4 header inside `buf` and ip_len_out to L3 length.
 * Returns 0 on success, -1 on no frame/error.
 */
int af_xdp_recv(af_xdp_t* x, uint8_t* buf, size_t buf_cap,
                const uint8_t** ip_out, size_t* ip_len_out);

/* Send one IPv4 payload by wrapping Ethernet header and publishing one
 * TX descriptor.
 */
int af_xdp_send_ipv4(af_xdp_t* x, const uint8_t* ip, size_t ip_len);

void af_xdp_close(af_xdp_t* x);

#endif
