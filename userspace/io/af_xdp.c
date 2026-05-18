#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "af_xdp.h"
#include "../xdp/xdp_loader.h"

#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#endif

/* Ring sizes: 4x bump (256→1024 RX/TX, 512→2048 FR/CR) so bursts of
 * parallel SYNs (e.g. browser opening 6+ concurrent sockets to load a
 * page) can land in the RX ring while the worker is mid-handshake on a
 * previous connection. With the original 256-entry RX ring, ~17–42% of
 * fresh handshakes were silently dropped at the XDP layer under typical
 * browser concurrency. UMEM frame count must be ≥ 2*FR (pre-fill is
 * FRAME_N/2). 16x bump tested first but kernel returned ENOBUFS on
 * UMEM_REG (likely cgroup memory accounting); 4x is conservative.
 *   UMEM = 4096 * 2048 = 8 MiB — well within the 128Mi pod memory limit.
 */
#define XSK_RX_RING_SZ 1024u
#define XSK_TX_RING_SZ 1024u
#define XSK_FR_RING_SZ 2048u
#define XSK_CR_RING_SZ 2048u
#define XSK_FRAME_SZ   2048u
#define XSK_FRAME_N    4096u

static inline uint32_t load_u32(uint32_t* p) {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}
static inline void store_u32(uint32_t* p, uint32_t v) {
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static int ring_init_desc(void* map, const struct xdp_ring_offset* o, uint32_t n,
                          uint32_t** prod, uint32_t** cons, uint32_t** flags,
                          struct xdp_desc** desc) {
    *prod  = (uint32_t*)((uint8_t*)map + o->producer);
    *cons  = (uint32_t*)((uint8_t*)map + o->consumer);
    *flags = (uint32_t*)((uint8_t*)map + o->flags);
    *desc  = (struct xdp_desc*)((uint8_t*)map + o->desc);
    (void)n;
    return 0;
}

static int ring_init_u64(void* map, const struct xdp_ring_offset* o, uint32_t n,
                         uint32_t** prod, uint32_t** cons, uint32_t** flags,
                         uint64_t** desc) {
    *prod  = (uint32_t*)((uint8_t*)map + o->producer);
    *cons  = (uint32_t*)((uint8_t*)map + o->consumer);
    *flags = (uint32_t*)((uint8_t*)map + o->flags);
    *desc  = (uint64_t*)((uint8_t*)map + o->desc);
    (void)n;
    return 0;
}

static void xdp_reap_completions(af_xdp_t* x) {
    static int comp_log_count = 0;
    uint32_t cons = load_u32(x->cr.consumer);
    uint32_t prod = load_u32(x->cr.producer);
    if (cons != prod && comp_log_count < 3) {
        fprintf(stderr, "af_xdp: completion ring: cons=%u prod=%u (completed=%u)\n", cons, prod, prod - cons);
        comp_log_count++;
    }
    while (cons != prod) {
        uint64_t addr = x->cr.desc[cons & x->cr.mask];
        if (x->tx_free_n < (uint32_t)(sizeof(x->tx_free) / sizeof(x->tx_free[0])))
            x->tx_free[x->tx_free_n++] = addr;
        cons++;
    }
    store_u32(x->cr.consumer, cons);
}

static int xdp_push_fill(af_xdp_t* x, uint64_t addr) {
    uint32_t prod = load_u32(x->fr.producer);
    uint32_t cons = load_u32(x->fr.consumer);
    if ((prod - cons) >= XSK_FR_RING_SZ) return -1;
    x->fr.desc[prod & x->fr.mask] = addr;
    store_u32(x->fr.producer, prod + 1);
    return 0;
}

int af_xdp_open(af_xdp_t* x, const char* ifname, uint32_t queue_id,
                const uint8_t local_mac[6], const uint8_t peer_mac[6]) {
#if !defined(__linux__)
    (void)x; (void)ifname; (void)queue_id; (void)local_mac; (void)peer_mac;
    return -1;
#else
    memset(x, 0, sizeof(*x));
    x->fd = -1;
    x->xdp_map_fd = -1;
    x->ifindex = if_nametoindex(ifname);
    if (x->ifindex == 0) return -1;
    x->queue_id = queue_id;
    memcpy(x->local_mac, local_mac, 6);
    memcpy(x->peer_mac, peer_mac, 6);
    x->frame_size = XSK_FRAME_SZ;
    x->frame_count = XSK_FRAME_N;
    x->umem_len = (size_t)x->frame_size * x->frame_count;

    x->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (x->fd < 0) return -1;

    x->umem = mmap(NULL, x->umem_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (x->umem == MAP_FAILED) { close(x->fd); x->fd = -1; return -1; }

    struct xdp_umem_reg um = {
        .addr = (uint64_t)(uintptr_t)x->umem,
        .len = (uint64_t)x->umem_len,
        .chunk_size = x->frame_size,
        .headroom = 0,
        .flags = 0,
    };
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &um, sizeof(um)) != 0) {
        fprintf(stderr, "af_xdp_open: XDP_UMEM_REG (umem=%zuB frame=%u nframes=%u): %s\n",
                x->umem_len, x->frame_size, x->frame_count, strerror(errno));
        goto fail;
    }
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_FILL_RING, &(uint32_t){XSK_FR_RING_SZ}, sizeof(uint32_t)) != 0) {
        fprintf(stderr, "af_xdp_open: XDP_UMEM_FILL_RING (sz=%u): %s\n", XSK_FR_RING_SZ, strerror(errno));
        goto fail;
    }
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &(uint32_t){XSK_CR_RING_SZ}, sizeof(uint32_t)) != 0) {
        fprintf(stderr, "af_xdp_open: XDP_UMEM_COMPLETION_RING (sz=%u): %s\n", XSK_CR_RING_SZ, strerror(errno));
        goto fail;
    }
    if (setsockopt(x->fd, SOL_XDP, XDP_RX_RING, &(uint32_t){XSK_RX_RING_SZ}, sizeof(uint32_t)) != 0) {
        fprintf(stderr, "af_xdp_open: XDP_RX_RING (sz=%u): %s\n", XSK_RX_RING_SZ, strerror(errno));
        goto fail;
    }
    if (setsockopt(x->fd, SOL_XDP, XDP_TX_RING, &(uint32_t){XSK_TX_RING_SZ}, sizeof(uint32_t)) != 0) {
        fprintf(stderr, "af_xdp_open: XDP_TX_RING (sz=%u): %s\n", XSK_TX_RING_SZ, strerror(errno));
        goto fail;
    }

    struct xdp_mmap_offsets off;
    socklen_t olen = sizeof(off);
    if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &olen) != 0) goto fail;

    x->rx_map_len = off.rx.desc + XSK_RX_RING_SZ * sizeof(struct xdp_desc);
    x->tx_map_len = off.tx.desc + XSK_TX_RING_SZ * sizeof(struct xdp_desc);
    x->fr_map_len = off.fr.desc + XSK_FR_RING_SZ * sizeof(uint64_t);
    x->cr_map_len = off.cr.desc + XSK_CR_RING_SZ * sizeof(uint64_t);

    x->rx_map = mmap(NULL, x->rx_map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, x->fd, XDP_PGOFF_RX_RING);
    x->tx_map = mmap(NULL, x->tx_map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, x->fd, XDP_PGOFF_TX_RING);
    x->fr_map = mmap(NULL, x->fr_map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, x->fd, XDP_UMEM_PGOFF_FILL_RING);
    x->cr_map = mmap(NULL, x->cr_map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, x->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (x->rx_map == MAP_FAILED || x->tx_map == MAP_FAILED ||
        x->fr_map == MAP_FAILED || x->cr_map == MAP_FAILED) goto fail;

    ring_init_desc(x->rx_map, &off.rx, XSK_RX_RING_SZ, &x->rx.producer, &x->rx.consumer, &x->rx.flags, &x->rx.desc);
    ring_init_desc(x->tx_map, &off.tx, XSK_TX_RING_SZ, &x->tx.producer, &x->tx.consumer, &x->tx.flags, &x->tx.desc);
    ring_init_u64(x->fr_map, &off.fr, XSK_FR_RING_SZ, &x->fr.producer, &x->fr.consumer, &x->fr.flags, &x->fr.desc);
    ring_init_u64(x->cr_map, &off.cr, XSK_CR_RING_SZ, &x->cr.producer, &x->cr.consumer, &x->cr.flags, &x->cr.desc);
    x->rx.mask = XSK_RX_RING_SZ - 1;
    x->tx.mask = XSK_TX_RING_SZ - 1;
    x->fr.mask = XSK_FR_RING_SZ - 1;
    x->cr.mask = XSK_CR_RING_SZ - 1;

    /* Load XDP redirect program BEFORE bind so the kernel knows packets
     * will be delivered via redirect (not copy mode). */
    x->xdp_map_fd = xdp_load_redirect(x->ifindex, 443);
    fprintf(stderr, "af_xdp: xdp_load_redirect(ifindex=%d, port=443) = %d (errno=%d)\n",
            x->ifindex, x->xdp_map_fd, x->xdp_map_fd < 0 ? errno : 0);

    struct sockaddr_xdp sxdp;
    memset(&sxdp, 0, sizeof(sxdp));
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_ifindex = (uint32_t)x->ifindex;
    sxdp.sxdp_queue_id = queue_id;
    sxdp.sxdp_flags = XDP_COPY;
    if (bind(x->fd, (struct sockaddr*)&sxdp, sizeof(sxdp)) != 0) {
        fprintf(stderr, "af_xdp: bind failed: errno=%d\n", errno);
        goto fail;
    }
    fprintf(stderr, "af_xdp: bind ok (fd=%d ifindex=%d queue=%u)\n", x->fd, x->ifindex, queue_id);

    if (x->xdp_map_fd >= 0) {
        /* Register this AF_XDP socket in the XSKMAP */
        union bpf_attr map_attr;
        memset(&map_attr, 0, sizeof(map_attr));
        map_attr.map_fd = x->xdp_map_fd;
        map_attr.key    = (uint64_t)(unsigned long)&(uint32_t){queue_id};
        map_attr.value  = (uint64_t)(unsigned long)&x->fd;
        map_attr.flags  = 0; /* BPF_ANY */
        int mr = (int)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map_attr, sizeof(map_attr));
        fprintf(stderr, "af_xdp: BPF_MAP_UPDATE_ELEM(map_fd=%d, key=%u, val=xsk_fd=%d) = %d (errno=%d)\n",
                x->xdp_map_fd, queue_id, x->fd, mr, mr != 0 ? errno : 0);
        if (mr != 0) goto fail;
    }

    /* Pre-populate fill ring with half the UMEM; reserve the other half for TX. */
    for (uint32_t i = 0; i < x->frame_count / 2; i++) {
        uint64_t addr = (uint64_t)i * x->frame_size;
        if (xdp_push_fill(x, addr) != 0) goto fail;
    }
    for (uint32_t i = x->frame_count / 2; i < x->frame_count; i++) {
        if (x->tx_free_n < (uint32_t)(sizeof(x->tx_free) / sizeof(x->tx_free[0])))
            x->tx_free[x->tx_free_n++] = (uint64_t)i * x->frame_size;
    }
    return 0;
fail:
    af_xdp_close(x);
    return -1;
#endif
}

int af_xdp_recv(af_xdp_t* x, uint8_t* buf, size_t buf_cap,
                const uint8_t** ip_out, size_t* ip_len_out) {
#if !defined(__linux__)
    (void)x; (void)buf; (void)buf_cap; (void)ip_out; (void)ip_len_out;
    return -1;
#else
    static int rx_log_count = 0;
    uint32_t cons = load_u32(x->rx.consumer);
    uint32_t prod = load_u32(x->rx.producer);
    if (cons == prod) return -1;

    const struct xdp_desc* d = &x->rx.desc[cons & x->rx.mask];

    if (rx_log_count < 20) {
        char hex[140];
        int hpos = 0;
        size_t dumplen = d->len < 66 ? d->len : 66;
        uint8_t *rxdata = (uint8_t*)x->umem + d->addr;
        for (size_t i = 0; i < dumplen && hpos < 132; i++)
            hpos += snprintf(hex + hpos, sizeof(hex) - hpos, "%02x", rxdata[i]);
        fprintf(stderr, "af_xdp: RX len=%u hex=%s\n", d->len, hex);
        rx_log_count++;
    }

    if (d->len > buf_cap || d->addr + d->len > x->umem_len) {
        store_u32(x->rx.consumer, cons + 1);
        (void)xdp_push_fill(x, d->addr);
        return -1;
    }
    memcpy(buf, (uint8_t*)x->umem + d->addr, d->len);
    store_u32(x->rx.consumer, cons + 1);
    (void)xdp_push_fill(x, d->addr);

    if (d->len < ETH_HDR_LEN) return -1;
    uint16_t ethertype = ((uint16_t)buf[12] << 8) | buf[13];
    if (ethertype != ETH_TYPE_IPV4) return -1;
    if (x->peer_mac[0] == 0 && x->peer_mac[1] == 0 &&
        x->peer_mac[2] == 0 && x->peer_mac[3] == 0 &&
        x->peer_mac[4] == 0 && x->peer_mac[5] == 0) {
        memcpy(x->peer_mac, buf + 6, 6);
    }
    *ip_out = buf + ETH_HDR_LEN;
    *ip_len_out = d->len - ETH_HDR_LEN;
    return 0;
#endif
}

int af_xdp_send_ipv4(af_xdp_t* x, const uint8_t* ip, size_t ip_len) {
#if !defined(__linux__)
    (void)x; (void)ip; (void)ip_len;
    return -1;
#else
    static int tx_log_count = 0;
    if (ip_len + ETH_HDR_LEN > x->frame_size) return -1;

    xdp_reap_completions(x);
    if (x->tx_free_n == 0) {
        if (tx_log_count < 5) { fprintf(stderr, "af_xdp: TX no free frames\n"); tx_log_count++; }
        return -1;
    }
    uint64_t addr = x->tx_free[--x->tx_free_n];
    if (addr + ip_len + ETH_HDR_LEN > x->umem_len) return -1;
    uint8_t* frame = (uint8_t*)x->umem + addr;
    memcpy(frame + 0, x->peer_mac, 6);
    memcpy(frame + 6, x->local_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;
    memcpy(frame + ETH_HDR_LEN, ip, ip_len);

    uint32_t prod = load_u32(x->tx.producer);
    uint32_t cons = load_u32(x->tx.consumer);
    if ((prod - cons) >= XSK_TX_RING_SZ) {
        x->tx_free[x->tx_free_n++] = addr;
        return -1;
    }
    struct xdp_desc* d = &x->tx.desc[prod & x->tx.mask];
    d->addr = addr;
    d->len = (uint32_t)(ETH_HDR_LEN + ip_len);
    d->options = 0;
    store_u32(x->tx.producer, prod + 1);

    /* Kick driver in need_wakeup mode. */
    int sr = (int)sendto(x->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (tx_log_count < 3) {
        char hex[140];
        int hpos = 0;
        size_t dumplen = ip_len + ETH_HDR_LEN;
        if (dumplen > 66) dumplen = 66;
        for (size_t i = 0; i < dumplen && hpos < 132; i++)
            hpos += snprintf(hex + hpos, sizeof(hex) - hpos, "%02x", frame[i]);
        fprintf(stderr, "af_xdp: TX len=%zu sendto=%d hex=%s\n",
                ip_len + ETH_HDR_LEN, sr, hex);
        tx_log_count++;
    }
    return (int)(ETH_HDR_LEN + ip_len);
#endif
}

void af_xdp_close(af_xdp_t* x) {
#if defined(__linux__)
    if (!x) return;
    if (x->xdp_map_fd >= 0) xdp_unload(x->ifindex, x->xdp_map_fd);
    if (x->rx_map && x->rx_map != MAP_FAILED) munmap(x->rx_map, x->rx_map_len);
    if (x->tx_map && x->tx_map != MAP_FAILED) munmap(x->tx_map, x->tx_map_len);
    if (x->fr_map && x->fr_map != MAP_FAILED) munmap(x->fr_map, x->fr_map_len);
    if (x->cr_map && x->cr_map != MAP_FAILED) munmap(x->cr_map, x->cr_map_len);
    if (x->umem && x->umem != MAP_FAILED) munmap(x->umem, x->umem_len);
    if (x->fd >= 0) close(x->fd);
    memset(x, 0, sizeof(*x));
    x->fd = -1;
    x->xdp_map_fd = -1;
#else
    (void)x;
#endif
}
