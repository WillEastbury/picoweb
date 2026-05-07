#ifndef METAL_SERVER_H
#define METAL_SERVER_H

#include <stdint.h>

#include "jumptable.h"

typedef enum {
    PICOWEB_BACKEND_EPOLL = 0,
    PICOWEB_BACKEND_URING,
    PICOWEB_BACKEND_DPDK,
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
} server_cfg_t;

/* Backend worker entrypoints. Each takes a server_cfg_t* and runs
 * the per-worker loop. Picked at runtime by main.c based on the
 * --io_uring / --dpdk flags. Default is epoll. */
void* epoll_worker_main(void* arg);
void* uring_worker_main(void* arg);
void* dpdk_worker_main(void* arg);

#endif
