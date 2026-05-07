#include "server.h"

#include <stdio.h>

#include "tls_bridge.h"
#include "util.h"

void* tls_worker_main(void* arg) {
    server_cfg_t* cfg = (server_cfg_t*)arg;
    if (!cfg || !cfg->jt) {
        metal_die("tls_worker_main: missing config");
    }
    if (!cfg->tls_ifname || !cfg->tls_ifname[0]) {
        metal_die("tls_worker_main: --tls-ifname is required");
    }
    if (!cfg->tls_cert_path || !cfg->tls_key_path) {
        metal_die("tls_worker_main: resolved TLS cert/key paths are required");
    }

    tls_bridge_t bridge;
    tls_bridge_init(&bridge, cfg->jt);

    /* Scaffold only: userspace AF_PACKET + TCP + TLS loop lands in
     * follow-up commits. We fail hard instead of silently falling back
     * to epoll so operators know the requested backend is unavailable. */
    fprintf(stderr,
        "picoweb: --tls backend scaffold active but data path not yet wired.\n"
        "         worker=%d listen=:%d ifname=%s cert=%s key=%s peer-mac=%s\n",
        cfg->worker_index, cfg->port, cfg->tls_ifname,
        cfg->tls_cert_path, cfg->tls_key_path,
        cfg->tls_peer_mac ? cfg->tls_peer_mac : "<auto>");
    (void)bridge;
    metal_die("--tls requested but backend runtime loop not integrated yet");
    return NULL;
}
