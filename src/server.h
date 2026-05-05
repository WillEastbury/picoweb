#ifndef METAL_SERVER_H
#define METAL_SERVER_H

#include <stdint.h>

#include "jumptable.h"

typedef struct {
    const jumptable_t* jt;
    int      port;
    size_t   pool_cap;             /* max connections per worker */
    int64_t  idle_ms;              /* idle timeout (any inactivity) in ms */
    uint32_t max_requests_per_conn;/* hard cap; 0 = unlimited */
    int      worker_index;         /* 0..N-1, for logging */
} server_cfg_t;

/* Run a worker thread loop. Never returns under normal operation; on
 * fatal error logs and exits the process. */
void* server_worker_main(void* arg);

#endif
