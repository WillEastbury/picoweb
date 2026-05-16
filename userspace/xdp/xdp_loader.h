#ifndef PICOWEB_XDP_LOADER_H
#define PICOWEB_XDP_LOADER_H

#include <stdint.h>

/* Load an XDP program that redirects TCP packets destined for `port`
 * to an XSKMAP, and passes all other traffic to the kernel.
 *
 * Returns the XSKMAP fd on success (caller owns it), or -1 on error.
 * The XDP program is attached to `ifindex` in SKB (generic) mode.
 *
 * After binding an AF_XDP socket, caller must update the XSKMAP:
 *   int key = queue_id;
 *   bpf(BPF_MAP_UPDATE_ELEM, {map_fd, &key, &xsk_fd, BPF_ANY});
 */
int xdp_load_redirect(int ifindex, uint16_t port);

/* Detach XDP program from interface and close map fd. */
void xdp_unload(int ifindex, int map_fd);

#endif
