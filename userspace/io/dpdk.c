/*
 * DPDK NIC backend for the picoweb userspace TCP+TLS pipeline.
 *
 * Compiles in two modes:
 *
 *   WITH_DPDK undefined (default in the spike test build)
 *     The whole file collapses to two stub functions that return -1.
 *     This keeps the rest of the userspace tree linkable on systems
 *     without DPDK headers/libraries (WSL, CI runners, dev laptops).
 *
 *   WITH_DPDK=1 (only on a real bare-metal Linux box with DPDK)
 *     Full RX-burst -> parse -> tcp_input -> TLS engine -> response
 *     -> tcp segment -> tx-burst pump using the rte_eal/ethdev/mbuf
 *     APIs. Picoweb's userspace stack does the protocol work; DPDK
 *     just owns the NIC queues and the mbuf pool.
 *
 * Why not link DPDK in always?
 *   - librte_eal et al. add ~2 MB of build deps + a kernel-side
 *     reconfigure (vfio-pci binding, hugepages) just to bench a
 *     static webserver.
 *   - WSL2 has no usable NIC for vfio-pci binding.
 *
 * Build a real DPDK picoweb-userspace with:
 *
 *   $(CC) $(CFLAGS) -DWITH_DPDK=1 \
 *         $(shell pkg-config --cflags libdpdk) \
 *         dpdk.c ... \
 *         $(shell pkg-config --libs libdpdk) -o picoweb_dpdk
 *
 * The userspace test build does NOT enable WITH_DPDK; pw_dpdk_init
 * and pw_dpdk_pump return -1 with a clear log line so a runtime
 * dispatch on `--dpdk` fails predictably.
 *
 * Same upstream interface either way:
 *   pw_dpdk_init(argc, argv, &cfg)   bring up EAL + port + queues
 *   pw_dpdk_pump(&ctx)               one RX/TX burst tick
 *   pw_dpdk_shutdown(&ctx)           drain + rte_eal_cleanup
 */

#include "dpdk.h"

#include <stdio.h>
#include <string.h>

/* ====================================================================== */
/* WITH_DPDK=0 — stub mode (default)                                      */
/* ====================================================================== */

#ifndef WITH_DPDK

int pw_dpdk_init(int argc, char** argv, pw_dpdk_cfg_t* cfg, pw_dpdk_ctx_t* out) {
    (void)argc; (void)argv; (void)cfg; (void)out;
    fprintf(stderr,
        "picoweb: DPDK backend not compiled in.\n"
        "Rebuild with -DWITH_DPDK=1 and link against libdpdk:\n"
        "  $(CC) -DWITH_DPDK=1 $(pkg-config --cflags libdpdk) ...\n"
        "      ... $(pkg-config --libs libdpdk) -o picoweb_dpdk\n"
        "Also requires: NIC bound to vfio-pci/uio_pci_generic, hugepages\n"
        "reserved (e.g. echo 1024 > /proc/sys/vm/nr_hugepages).\n");
    return -1;
}

int pw_dpdk_pump(pw_dpdk_ctx_t* ctx) {
    (void)ctx;
    return -1;
}

void pw_dpdk_shutdown(pw_dpdk_ctx_t* ctx) {
    (void)ctx;
}

#else  /* WITH_DPDK */

/* ====================================================================== */
/* WITH_DPDK=1 — real DPDK pump                                           */
/* ====================================================================== */

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "../tcp/ip.h"
#include "../tcp/tcp.h"
#include "../tls/engine.h"
#include "../tls/engine_pool.h"
#include "../conn.h"
#include "af_packet.h"   /* ETH_TYPE_IPV4 */

#define PW_DPDK_RX_BURST   32
#define PW_DPDK_TX_BURST   32
#define PW_DPDK_MEMPOOL_N  8192
#define PW_DPDK_MBUF_DATA  RTE_MBUF_DEFAULT_BUF_SIZE
#define PW_DPDK_MBUF_CACHE 256

/* Convert one mbuf (Ethernet frame) into a parsed IPv4+TCP segment
 * and feed it into the userspace TCP layer. Returns 0 if consumed,
 * -1 if not for us (non-IPv4, non-TCP, malformed). */
static int handle_one_rx_mbuf(pw_dpdk_ctx_t* ctx, struct rte_mbuf* m) {
    const uint8_t* eth = rte_pktmbuf_mtod(m, const uint8_t*);
    uint16_t       len = rte_pktmbuf_pkt_len(m);

    /* 14-byte Ethernet header. We only handle untagged IPv4 here;
     * VLAN/IPv6 are out of scope for the spike. */
    if (len < 14) return -1;
    uint16_t etype = (uint16_t)((eth[12] << 8) | eth[13]);
    if (etype != ETH_TYPE_IPV4) return -1;   /* not IPv4 */

    const uint8_t* l3 = eth + 14;
    size_t l3_len = (size_t)len - 14;

    tcp_seg_t parsed;
    if (ip_tcp_parse(l3, l3_len, &parsed) != 0) return -1;
    /* ip_tcp_parse already verified IPv4 + proto==6; nothing more to filter. */

    /* Hand the parsed segment to the TCP state machine; it returns
     * any plaintext (post-TLS) ready for response_fn dispatch via
     * the configured pw_conn or pw_tls_engine. ctx->on_segment owns
     * the response build + TX enqueue. */
    return ctx->on_segment ? ctx->on_segment(ctx, &parsed) : 0;
}

int pw_dpdk_init(int argc, char** argv, pw_dpdk_cfg_t* cfg, pw_dpdk_ctx_t* out) {
    if (!cfg || !out) return -1;
    memset(out, 0, sizeof(*out));

    int eal_args = rte_eal_init(argc, argv);
    if (eal_args < 0) {
        fprintf(stderr, "picoweb: rte_eal_init failed\n");
        return -1;
    }

    out->mempool = rte_pktmbuf_pool_create(
        "pw_mbuf_pool", PW_DPDK_MEMPOOL_N, PW_DPDK_MBUF_CACHE,
        0, PW_DPDK_MBUF_DATA, rte_socket_id());
    if (!out->mempool) {
        fprintf(stderr, "picoweb: rte_pktmbuf_pool_create failed\n");
        return -1;
    }

    out->port_id = cfg->port_id;
    struct rte_eth_conf eth_conf;
    memset(&eth_conf, 0, sizeof(eth_conf));
    if (rte_eth_dev_configure(out->port_id, 1, 1, &eth_conf) < 0) {
        fprintf(stderr, "picoweb: rte_eth_dev_configure failed\n");
        return -1;
    }

    if (rte_eth_rx_queue_setup(out->port_id, 0, 1024,
                               rte_eth_dev_socket_id(out->port_id),
                               NULL, out->mempool) < 0) return -1;
    if (rte_eth_tx_queue_setup(out->port_id, 0, 1024,
                               rte_eth_dev_socket_id(out->port_id),
                               NULL) < 0) return -1;
    if (rte_eth_dev_start(out->port_id) < 0) return -1;
    rte_eth_promiscuous_enable(out->port_id);

    out->on_segment   = cfg->on_segment;
    out->on_tick      = cfg->on_tick;
    out->user         = cfg->user;
    out->initialised  = 1;
    return 0;
}

int pw_dpdk_pump(pw_dpdk_ctx_t* ctx) {
    if (!ctx || !ctx->initialised) return -1;

    struct rte_mbuf* rx[PW_DPDK_RX_BURST];
    uint16_t n = rte_eth_rx_burst(ctx->port_id, 0, rx, PW_DPDK_RX_BURST);

    for (uint16_t i = 0; i < n; i++) {
        (void)handle_one_rx_mbuf(ctx, rx[i]);
        rte_pktmbuf_free(rx[i]);
    }

    /* Tick the owner's timer wheel between RX drain and TX flush so
     * any retransmits / RTO-driven sends scheduled by tcp_tick are
     * batched into the same TX burst as application sends. */
    if (ctx->on_tick) ctx->on_tick(ctx);

    /* TX side: ctx->on_segment is expected to enqueue prepared
     * mbufs into ctx->tx_pending; we drain them here in one burst. */
    if (ctx->tx_pending_n > 0) {
        uint16_t sent = rte_eth_tx_burst(ctx->port_id, 0,
                                         ctx->tx_pending,
                                         ctx->tx_pending_n);
        for (uint16_t i = sent; i < ctx->tx_pending_n; i++) {
            rte_pktmbuf_free(ctx->tx_pending[i]);   /* drop on overflow */
        }
        ctx->tx_pending_n = 0;
    }

    return (int)n;
}

void pw_dpdk_shutdown(pw_dpdk_ctx_t* ctx) {
    if (!ctx || !ctx->initialised) return;
    rte_eth_dev_stop(ctx->port_id);
    rte_eth_dev_close(ctx->port_id);
    rte_eal_cleanup();
    ctx->initialised = 0;
}

#endif /* WITH_DPDK */
