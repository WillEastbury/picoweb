#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jumptable.h"
#include "metrics.h"
#include "server.h"
#include "simd.h"
#include "util.h"

static void usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s [PORT] [WWWROOT] [WORKERS] [MAXREQS] [ZC_MIN]\n"
        "  PORT     listen port (default 8080)\n"
        "  WWWROOT  content root (default ./wwwroot)\n"
        "  WORKERS  worker threads (default = nproc)\n"
        "  MAXREQS  max requests per connection (default 100; 0 = unlimited)\n"
        "  ZC_MIN   MSG_ZEROCOPY threshold in bytes (default 0 = off;\n"
        "           recommended 16384 if enabled — small payloads regress)\n",
        argv0);
}

int main(int argc, char** argv) {
    int port = 8080;
    const char* wwwroot = "wwwroot";
    long workers = sysconf(_SC_NPROCESSORS_ONLN);
    if (workers < 1) workers = 1;
    long max_reqs = 100;
    long zc_min = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            usage(argv[0]); return 0;
        }
        char* end = NULL;
        long p = strtol(argv[1], &end, 10);
        if (end == argv[1] || *end != '\0' || p < 1 || p > 65535) {
            usage(argv[0]); return 1;
        }
        port = (int)p;
    }
    if (argc > 2) wwwroot = argv[2];
    if (argc > 3) {
        char* end = NULL;
        long w = strtol(argv[3], &end, 10);
        if (end == argv[3] || *end != '\0' || w < 1 || w > 1024) {
            usage(argv[0]); return 1;
        }
        workers = w;
    }
    if (argc > 4) {
        char* end = NULL;
        long m = strtol(argv[4], &end, 10);
        if (end == argv[4] || *end != '\0' || m < 0 || m > 1000000) {
            usage(argv[0]); return 1;
        }
        max_reqs = m;
    }
    if (argc > 5) {
        char* end = NULL;
        long z = strtol(argv[5], &end, 10);
        if (end == argv[5] || *end != '\0' || z < 0 || z > (long)(64*1024*1024)) {
            usage(argv[0]); return 1;
        }
        zc_min = z;
    }

    /* SIGPIPE: ignore so writes to a peer-closed socket return EPIPE
     * instead of killing the process. (We also pass MSG_NOSIGNAL on
     * sendmsg, so this is belt and braces.) */
    signal(SIGPIPE, SIG_IGN);

    /* Initialize per-worker metrics state. MUST happen before
     * jumptable_build (which calls metrics_build_resources for /stats). */
    metrics_init((int)workers);

    /* Build the immutable jump table once on the main thread. */
    static jumptable_t jt;
    if (!jumptable_build(&jt, wwwroot)) {
        return 2;
    }

    /* Spawn workers. */
    pthread_t* threads = (pthread_t*)calloc((size_t)workers, sizeof(pthread_t));
    server_cfg_t* cfgs = (server_cfg_t*)calloc((size_t)workers, sizeof(server_cfg_t));
    if (!threads || !cfgs) { metal_die("oom workers"); }

    for (long i = 0; i < workers; i++) {
        cfgs[i].jt                    = &jt;
        cfgs[i].port                  = port;
        cfgs[i].pool_cap              = 4096;
        cfgs[i].idle_ms               = 10000;  /* 10s any-inactivity cap */
        cfgs[i].max_requests_per_conn = (uint32_t)max_reqs;
        cfgs[i].worker_index          = (int)i;
        cfgs[i].zerocopy_threshold    = (size_t)zc_min;
        if (pthread_create(&threads[i], NULL, server_worker_main, &cfgs[i]) != 0) {
            metal_die("pthread_create #%ld", i);
        }
    }

    /* Background thread that rebuilds the /stats body once per second. */
    metrics_start_updater();

    metal_log("picoweb: %ld worker(s) on :%d, root=%s, maxreqs=%ld, "
              "zerocopy=%s, simd=%s",
              workers, port, wwwroot, max_reqs,
              zc_min > 0 ? "on" : "off", metal_simd_describe());
    if (zc_min > 0) {
        metal_log("picoweb: MSG_ZEROCOPY threshold = %ld bytes", zc_min);
    }

    for (long i = 0; i < workers; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
