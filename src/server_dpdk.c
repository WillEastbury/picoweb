/*
 * DPDK backend stub.
 *
 * The real DPDK code path requires:
 *   - librte_eal, librte_ethdev, librte_mbuf, librte_mempool
 *   - kernel-side vfio-pci or uio_pci_generic with a NIC bound
 *   - hugepages reserved
 *   - the picoweb userspace TCP+TLS stack (see userspace/) wired
 *     through to feed RX bursts into tcp_input() and send via
 *     rte_eth_tx_burst().
 *
 * None of those dependencies are present in the default picoweb
 * build, so this stub exists to (a) reserve the --dpdk runtime
 * flag in the CLI parser, and (b) print a clear, actionable error
 * pointing the operator at the DESIGN.md scope doc.
 *
 * Building a real DPDK backend means dropping in an additional .c
 * file that overrides this symbol (or compiling with DPDK_BACKEND=1
 * and #ifdef'ing the body in). For now, this stub keeps the rest of
 * the binary linkable without taking a hard dependency on RTE.
 */

#include <stdio.h>
#include <stdlib.h>

#include "server.h"
#include "util.h"

void* dpdk_worker_main(void* arg) {
    (void)arg;
    fprintf(stderr,
        "picoweb: --dpdk backend is not built into this binary.\n"
        "\n"
        "Building it requires:\n"
        "  * DPDK runtime libraries (librte_eal et al.)\n"
        "  * a NIC bound to vfio-pci or uio_pci_generic (driver detached)\n"
        "  * hugepages reserved (e.g. echo 1024 > /proc/sys/vm/nr_hugepages)\n"
        "  * the userspace TCP+TLS stack from userspace/ wired in\n"
        "\n"
        "See userspace/DESIGN.md and userspace/io/dpdk_sketch.c for the\n"
        "intended integration shape. picoweb will not run with --dpdk\n"
        "until that work is done.\n");
    /* Per-worker stub: rather than tearing down the whole process here
     * (which would race with siblings), we exit non-zero so the caller
     * sees a clear failure. main.c also rejects --dpdk before spawning
     * workers; this body is defence-in-depth in case that gate is ever
     * removed. */
    metal_die("--dpdk requested but DPDK backend not built");
    return NULL;
}
