#ifndef METAL_SERVER_H
#define METAL_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jumptable.h"

typedef enum {
    PICOWEB_BACKEND_EPOLL = 0,
    PICOWEB_BACKEND_URING,
    PICOWEB_BACKEND_DPDK,
    PICOWEB_BACKEND_TLS,
} picoweb_backend_t;

typedef struct {
    const jumptable_t* jt;
    int      port;
    size_t   pool_cap;             /* max connections per worker */
    int64_t  idle_ms;              /* idle timeout (any inactivity) in ms */
    uint32_t max_requests_per_conn;/* hard cap; 0 = unlimited */
    int      worker_index;         /* 0..N-1, for logging */
    /* MSG_ZEROCOPY threshold in bytes. 0 = disabled (default). When non-
     * zero, accepted sockets are opted in via setsockopt(SO_ZEROCOPY) and
     * sendmsg ORs in MSG_ZEROCOPY for any response whose total wire
     * payload (head + chrome + body) is >= this many bytes. Small
     * payloads bypass it because the per-send setup cost typically
     * outweighs the saved copy below ~10 KB. */
    size_t   zerocopy_threshold;

    /* io_uring SQPOLL: kernel polls our submission queue, eliminating
     * io_uring_enter() syscalls on the submit path entirely. Costs one
     * dedicated kernel thread per worker (sleeps after sq_thread_idle_ms
     * of inactivity). sqpoll_cpu pins the kernel thread to a specific
     * CPU; -1 = unpinned. Ignored by epoll/dpdk backends. */
    bool     sqpoll;
    int      sqpoll_cpu;

    /* Userspace TLS backend knobs. Ignored by epoll/io_uring/dpdk. */
    const char* tls_cert_path;
    const char* tls_key_path;
    const char* tls_ifname;
    const char* tls_peer_mac;
    bool        tls_use_xdp;
    uint32_t    tls_xdp_queue;

    /* HTTP 103 Early Hints. When true, GET responses for HTML resources
     * with a precomputed Link header (built from <link>/<script>/<img>/
     * <source> references found at startup) are preceded on the wire by
     * an interim "HTTP/1.1 103 Early Hints" response sealed in its own
     * TLS record. Same hints are also embedded in the final 200 head.
     * Skipped for HEAD, conditional GETs that would 304, and for
     * resources without a Link header. Off by default. */
    bool        http_early_hints;
} server_cfg_t;

/* Backend worker entrypoints. Each takes a server_cfg_t* and runs
 * the per-worker loop. Picked at runtime by main.c based on the
 * --io_uring / --dpdk flags. Default is epoll. */
void* epoll_worker_main(void* arg);
void* uring_worker_main(void* arg);
void* dpdk_worker_main(void* arg);
void* tls_worker_main(void* arg);

/* Process-wide graceful shutdown state. Signal waiters only set this flag;
 * each worker closes its own listen socket after the lameduck window and
 * exits after active connections drain or the hard drain deadline expires. */
void server_request_shutdown(int signo);
bool server_shutdown_requested(void);
bool server_shutdown_lameduck_elapsed(void);
bool server_shutdown_force_close(void);
int  server_shutdown_signal(void);

#endif
