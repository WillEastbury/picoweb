/*
 * DPDK NIC backend — public interface. See dpdk.c for build modes.
 *
 * Stub-by-default: pw_dpdk_init returns -1 and prints an actionable
 * error unless the file was compiled with -DWITH_DPDK=1. Use this
 * shape so the userspace pipeline can be linked into a binary
 * regardless of whether DPDK is available on the build host.
 */
#ifndef PICOWEB_USERSPACE_IO_DPDK_H
#define PICOWEB_USERSPACE_IO_DPDK_H

#include <stddef.h>
#include <stdint.h>

#include "../tcp/ip.h"

#define PW_DPDK_TX_PENDING_MAX 32

typedef struct pw_dpdk_ctx pw_dpdk_ctx_t;

/* Per-segment dispatch callback. Called from `pw_dpdk_pump` for each
 * parsed IPv4+TCP segment lifted off the RX ring. Returns 0 on
 * success, -1 to drop. The callback is expected to push any
 * outbound mbufs onto ctx->tx_pending[]. */
typedef int (*pw_dpdk_on_segment_fn)(pw_dpdk_ctx_t* ctx,
                                     const tcp_seg_t* seg);

/* Per-pump tick callback. Called from `pw_dpdk_pump` AFTER the RX
 * burst is drained but BEFORE the TX flush, so that any retransmits
 * scheduled by the tick (e.g. tcp_tick on RTO expiry) ride out in the
 * same TX burst. The owner is expected to read its own monotonic
 * clock and call tcp_tick(stack, now_ms, ...). May be NULL. */
typedef void (*pw_dpdk_on_tick_fn)(pw_dpdk_ctx_t* ctx);

typedef struct {
    int                    port_id;        /* rte_eth_dev port index */
    pw_dpdk_on_segment_fn  on_segment;
    pw_dpdk_on_tick_fn     on_tick;        /* optional */
    void*                  user;
} pw_dpdk_cfg_t;

struct pw_dpdk_ctx {
    int                   port_id;
    void*                 mempool;          /* struct rte_mempool* in WITH_DPDK build */
    pw_dpdk_on_segment_fn on_segment;
    pw_dpdk_on_tick_fn    on_tick;
    void*                 user;
    int                   initialised;
    /* Caller-staged TX mbufs to drain in the next pump tick. */
    void*                 tx_pending[PW_DPDK_TX_PENDING_MAX];   /* struct rte_mbuf* */
    uint16_t              tx_pending_n;
};

/* Initialise EAL + a single RX/TX queue on cfg->port_id. argc/argv
 * are passed straight to rte_eal_init (use --lcores, -l, etc.).
 * Returns 0 on success, -1 on any failure (stub mode always
 * returns -1 with a helpful message). */
int  pw_dpdk_init(int argc, char** argv, pw_dpdk_cfg_t* cfg,
                  pw_dpdk_ctx_t* out);

/* One pump tick: drain RX (up to PW_DPDK_RX_BURST mbufs) and call
 * ctx->on_segment for each parsed segment, then flush
 * ctx->tx_pending via rte_eth_tx_burst. Returns mbufs received this
 * tick, or -1 on error. */
int  pw_dpdk_pump(pw_dpdk_ctx_t* ctx);

/* Stop the port, close it, rte_eal_cleanup. No-op in stub mode. */
void pw_dpdk_shutdown(pw_dpdk_ctx_t* ctx);

/* Bounded TX enqueue helper. Returns 0 on success, -1 if the ring
 * is full (caller should drop the mbuf — pump will not free it).
 *
 * mbuf-ownership contract for owners of the on_segment callback:
 *   - The mbuf passed into on_segment is owned by the RX-drain loop
 *     in pw_dpdk_pump and is freed after on_segment returns; on_segment
 *     MUST NOT retain a pointer to it (no zero-copy hand-off).
 *   - mbufs pushed into ctx->tx_pending via this helper transfer
 *     ownership to the pump; pump frees any mbufs not accepted by
 *     rte_eth_tx_burst. */
static inline int pw_dpdk_tx_enqueue(pw_dpdk_ctx_t* ctx, void* mbuf) {
    if (!ctx || !mbuf) return -1;
    if (ctx->tx_pending_n >= PW_DPDK_TX_PENDING_MAX) return -1;
    ctx->tx_pending[ctx->tx_pending_n++] = mbuf;
    return 0;
}

#endif
