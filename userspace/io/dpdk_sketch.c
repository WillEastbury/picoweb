/*
 * DPDK / AF_XDP integration sketch — NOT BUILT.
 *
 * This file documents what the actual NIC-bypass path would look
 * like for picoweb-userspace. It does not link into the spike test
 * suite; it exists so future work has a starting point.
 *
 * ----------------------------------------------------------------
 * DPDK path
 * ----------------------------------------------------------------
 *
 * Dependencies (rejected for now per "no 3p libraries"):
 *   - librte_eal, librte_ethdev, librte_mbuf, librte_mempool
 *   - libnuma, kernel module rte_kni / vfio-pci
 *
 * Setup:
 *   1. Bind a NIC to vfio-pci or uio_pci_generic (driver detached).
 *   2. Allocate hugepages (typically 2 MiB pages, 1024+ pages).
 *   3. rte_eal_init(argc, argv) — picks lcores, hugepage mounts.
 *   4. Per-port: rte_eth_dev_configure(port, nb_rx_q, nb_tx_q).
 *      Configure offloads (TX_CHECKSUM, TSO if you care).
 *   5. Per-queue: rte_eth_rx_queue_setup, rte_eth_tx_queue_setup with
 *      a pre-allocated mempool of mbufs.
 *   6. rte_eth_dev_start.
 *
 * RX poll loop (per lcore):
 *
 *   struct rte_mbuf* bufs[BURST];
 *   while (1) {
 *     uint16_t n = rte_eth_rx_burst(port, queue, bufs, BURST);
 *     for (uint16_t i = 0; i < n; i++) {
 *       const uint8_t* eth = rte_pktmbuf_mtod(bufs[i], const uint8_t*);
 *       // strip ethernet, hand IP + TCP up to tcp_input()
 *     }
 *     rte_pktmbuf_free_bulk(bufs, n);
 *   }
 *
 * TX:
 *
 *   struct rte_mbuf* m = rte_pktmbuf_alloc(pool);
 *   uint8_t* p = rte_pktmbuf_append(m, eth_len + ip_len);
 *   // build eth + ip + tcp into p
 *   rte_eth_tx_burst(port, queue, &m, 1);
 *
 * Pinning:
 *   - rte_eal_remote_launch() per lcore.
 *   - --lcores=0-7 or pin by lcore_role via rte_lcore_id().
 *
 * Why not yet:
 *   - Adds ~2 MB of build dependencies and a kernel-side reconfigure
 *     to the user's box just to bench a static webserver.
 *   - WSL has no usable NIC for vfio-pci binding; can only run on a
 *     bare-metal Linux test box.
 *   - The tcp.c here doesn't do retransmits or congestion control;
 *     pumping it via DPDK would expose every gap immediately.
 *
 * ----------------------------------------------------------------
 * AF_XDP path (lighter)
 * ----------------------------------------------------------------
 *
 * AF_XDP gives you DMA-into-userspace rings without removing the NIC
 * driver. You still pay for the in-kernel XDP program but skip the
 * full kernel stack.
 *
 *   socket(AF_XDP, SOCK_RAW, 0)
 *   setsockopt(XDP_UMEM_REG, ...)         // register frame area
 *   setsockopt(XDP_RX_RING, ...)          // setup RX descriptor ring
 *   setsockopt(XDP_TX_RING, ...)
 *   mmap(...) the four rings (FILL, COMP, RX, TX)
 *   bind(AF_XDP, ifindex/queue)
 *   attach an XDP_REDIRECT BPF program that punts matching IPv4 TCP
 *   packets to the AF_XDP socket
 *
 * Pros:  no driver detach, only the matched flow goes userspace.
 * Cons:  needs a tiny BPF program (libbpf or hand-rolled load).
 *
 * Both paths share the same upstream interface with this spike: feed
 * an IPv4+TCP buffer into ip_tcp_parse() then tcp_input(). The only
 * thing that changes is the NIC driver glue.
 */
