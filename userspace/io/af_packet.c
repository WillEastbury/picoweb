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
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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
    return 0;
#endif
}

int af_packet_recv(af_packet_t* a,
                   uint8_t* buf, size_t buf_cap,
                   const uint8_t** ip_out, size_t* ip_len_out) {
#if !defined(__linux__)
    (void)a; (void)buf; (void)buf_cap; (void)ip_out; (void)ip_len_out;
    return -1;
#else
    ssize_t n = recv(a->fd, buf, buf_cap, 0);
    if (n < (ssize_t)ETH_HDR_LEN) return -1;
    uint16_t ethertype = ((uint16_t)buf[12] << 8) | buf[13];
    if (ethertype != ETH_TYPE_IPV4) return -1;
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
