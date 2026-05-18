/*
 * AF_PACKET RX/TX skeleton.
 *
 * Spike-grade. Compiles on Linux; will not run end-to-end inside
 * WSL2 because there is no NIC to bind raw L2 to.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "af_packet.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* These headers only exist on Linux. We guard the file so it still
 * compiles on macOS / Windows for IDE purposes — the body simply
 * returns -1 in that case. */
#if defined(__linux__)
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif

int af_packet_open(af_packet_t* a, const char* ifname,
                   const uint8_t local_mac[6],
                   const uint8_t peer_mac[6]) {
#if !defined(__linux__)
    (void)a; (void)ifname; (void)local_mac; (void)peer_mac;
    return -1;
#else
    memset(a, 0, sizeof(*a));
    memcpy(a->local_mac, local_mac, 6);
    memcpy(a->peer_mac,  peer_mac,  6);

    a->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_TYPE_IPV4));
    if (a->fd < 0) return -1;

    /* Enable auxiliary data so recvmsg() delivers TP_STATUS flags
     * (we need TP_STATUS_CSUMNOTREADY for veth/virtual interfaces
     * where TX checksum offload leaves the field incomplete). */
    int val = 1;
    setsockopt(a->fd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(a->fd, SIOCGIFINDEX, &ifr) < 0) { close(a->fd); return -1; }
    a->ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_TYPE_IPV4);
    sll.sll_ifindex  = a->ifindex;
    if (bind(a->fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(a->fd); return -1;
    }

    /* Bump SO_RCVBUF so bursts of unrelated traffic on the veth don't
     * cause in-kernel drops while we're servicing a request. Best-
     * effort: kernel may cap at /proc/sys/net/core/rmem_max. */
    int rcvbuf = 4 * 1024 * 1024;
    (void)setsockopt(a->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    return 0;
#endif
}

int af_packet_install_filter(af_packet_t* a,
                             uint32_t local_ip_be,
                             uint16_t dst_port_host) {
#if !defined(__linux__)
    (void)a; (void)local_ip_be; (void)dst_port_host;
    return -1;
#else
    if (!a || a->fd < 0) return -1;

    /* Don't reflect our own TX back to the RX path. Best-effort:
     * kernel < 4.20 doesn't have this option; ignore the error. */
    int one = 1;
    (void)setsockopt(a->fd, SOL_PACKET, PACKET_IGNORE_OUTGOING,
                     &one, sizeof(one));

    /* Classic-BPF program:
     *   if (eth.type != IPv4)            drop;
     *   if (ip.proto != TCP)             drop;
     *   if (ip.dst   != local_ip)        drop;
     *   X = (ip.ihl & 0xf) * 4;          // L4 offset relative to L3
     *   if (tcp.dst  != dst_port)        drop;
     *   accept (return 65535).
     *
     * BPF offsets are absolute from the start of the link-layer
     * frame, so L3 starts at +14 (Ethernet) and TCP dst port lives
     * at L3+ihl*4+2. We use BPF_LDX|BPF_B|BPF_MSH to compute IHL*4
     * into X, then load the half-word at [X + 14 + 2]. */
    struct sock_filter prog[] = {
        { 0x28, 0, 0, 0x0000000c },                       /* ldh [12]                       */
        { 0x15, 0, 7, 0x00000800 },                       /* jne #ETH_P_IP, drop            */
        { 0x30, 0, 0, 0x00000017 },                       /* ldb [23]                       */
        { 0x15, 0, 5, 0x00000006 },                       /* jne #IPPROTO_TCP, drop         */
        { 0x20, 0, 0, 0x0000001e },                       /* ld  [30]   ; ip dst            */
        { 0x15, 0, 3, ntohl(local_ip_be) },               /* jne #LOCAL, drop               */
        { 0xb1, 0, 0, 0x0000000e },                       /* ldxb 4*([14]&0xf)              */
        { 0x48, 0, 0, 0x00000010 },                       /* ldh [x + 16] ; tcp dst (14+2)  */
        { 0x15, 0, 1, dst_port_host },                    /* jne #PORT, drop                */
        { 0x06, 0, 0, 0x0000ffff },                       /* ret #65535                     */
        { 0x06, 0, 0, 0x00000000 },                       /* drop: ret #0                   */
    };
    struct sock_fprog fprog = {
        .len = (unsigned short)(sizeof(prog) / sizeof(prog[0])),
        .filter = prog,
    };
    if (setsockopt(a->fd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &fprog, sizeof(fprog)) < 0) {
        return -1;
    }
    return 0;
#endif
}

int af_packet_recv(af_packet_t* a,
                   uint8_t* buf, size_t buf_cap,
                   const uint8_t** ip_out, size_t* ip_len_out,
                   int* csum_not_ready) {
#if !defined(__linux__)
    (void)a; (void)buf; (void)buf_cap; (void)ip_out; (void)ip_len_out;
    (void)csum_not_ready;
    return -1;
#else
    *csum_not_ready = 0;

    struct iovec iov = { .iov_base = buf, .iov_len = buf_cap };
    union {
        struct cmsghdr cmsg;
        uint8_t buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = &cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };

    ssize_t n = recvmsg(a->fd, &msg, 0);
    if (n < (ssize_t)ETH_HDR_LEN) return -1;

    /* Check for TP_STATUS_CSUMNOTREADY in auxiliary data. */
    for (struct cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm;
         cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_PACKET &&
            cm->cmsg_type  == PACKET_AUXDATA) {
            struct tpacket_auxdata* aux =
                (struct tpacket_auxdata*)CMSG_DATA(cm);
            if (aux->tp_status & TP_STATUS_CSUMNOTREADY)
                *csum_not_ready = 1;
        }
    }

    uint16_t ethertype = ((uint16_t)buf[12] << 8) | buf[13];
    if (ethertype != ETH_TYPE_IPV4) return -1;
    if (a->peer_mac[0] == 0 && a->peer_mac[1] == 0 &&
        a->peer_mac[2] == 0 && a->peer_mac[3] == 0 &&
        a->peer_mac[4] == 0 && a->peer_mac[5] == 0) {
        memcpy(a->peer_mac, buf + 6, 6);
    }
    *ip_out = buf + ETH_HDR_LEN;
    *ip_len_out = (size_t)n - ETH_HDR_LEN;
    return 0;
#endif
}

int af_packet_send_ipv4(af_packet_t* a,
                        const uint8_t* ip, size_t ip_len) {
#if !defined(__linux__)
    (void)a; (void)ip; (void)ip_len;
    return -1;
#else
    uint8_t frame[1518];
    if (ip_len + ETH_HDR_LEN > sizeof(frame)) return -1;
    memcpy(frame + 0, a->peer_mac,  6);
    memcpy(frame + 6, a->local_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;
    memcpy(frame + ETH_HDR_LEN, ip, ip_len);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_TYPE_IPV4);
    sll.sll_ifindex  = a->ifindex;
    sll.sll_halen    = 6;
    memcpy(sll.sll_addr, a->peer_mac, 6);

    ssize_t n = sendto(a->fd, frame, ip_len + ETH_HDR_LEN, 0,
                       (struct sockaddr*)&sll, sizeof(sll));
    return n < 0 ? -1 : (int)n;
#endif
}

void af_packet_close(af_packet_t* a) {
#if defined(__linux__)
    if (a && a->fd >= 0) { close(a->fd); a->fd = -1; }
#else
    (void)a;
#endif
}
