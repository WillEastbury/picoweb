#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "jumptable.h"
#include "metrics.h"
#include "server.h"
#include "simd.h"
#include "util.h"

static void usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s [--io_uring | --dpdk] [--sqpoll [--sqpoll-cpu=N]] [PORT] [WWWROOT] [WORKERS] [MAXREQS] [ZC_MIN] [POOL_CAP]\n"
        "\n"
        "  --io_uring   use the io_uring worker backend (Linux 5.6+, no liburing)\n"
        "  --dpdk       use the DPDK userspace backend (NOT BUILT — see\n"
        "               userspace/DESIGN.md; the flag is reserved and will\n"
        "               error out at startup until the integration ships)\n"
        "  --sqpoll     enable IORING_SETUP_SQPOLL: kernel polls our SQ,\n"
        "               eliminating io_uring_enter() syscalls on the submit\n"
        "               path. Costs one kernel thread per worker. Requires\n"
        "               --io_uring. Best for sustained high-throughput loads.\n"
        "  --sqpoll-cpu=N  pin SQPOLL kernel threads starting at CPU N\n"
        "                  (worker i -> CPU (N+i) mod nproc). Implies --sqpoll.\n"
        "\n"
        "  PORT      listen port (default 8080)\n"
        "  WWWROOT   content root (default ./wwwroot)\n"
        "  WORKERS   worker threads (default = nproc)\n"
        "  MAXREQS   max requests per connection (default 100; 0 = unlimited)\n"
        "  ZC_MIN    MSG_ZEROCOPY threshold in bytes (default 0 = off;\n"
        "            recommended 16384 if enabled — small payloads regress)\n"
        "  POOL_CAP  max concurrent connections per worker (default 4096;\n"
        "            each slot costs ~8KB RSS — use 64-256 for low-traffic sites)\n"
        "\n"
        "Default backend is epoll. --io_uring and --dpdk are mutually exclusive.\n",
        argv0);
}

int main(int argc, char** argv) {
    int port = 8080;
    const char* wwwroot = "wwwroot";
    long workers = sysconf(_SC_NPROCESSORS_ONLN);
    if (workers < 1) workers = 1;
    long max_reqs = 100;
    long zc_min = 0;
    long pool_cap = 4096;
    picoweb_backend_t backend = PICOWEB_BACKEND_EPOLL;
    bool sqpoll = false;
    int  sqpoll_cpu = -1;

    /* Two-pass parse: lift flags out of argv first, then handle the
     * remaining positional args exactly as before. This keeps the
     * existing positional CLI 100% backwards compatible. */
    char* pos[16];
    int   npos = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        }
        if (strcmp(argv[i], "--io_uring") == 0 ||
            strcmp(argv[i], "--io-uring") == 0) {
            if (backend != PICOWEB_BACKEND_EPOLL) {
                fprintf(stderr, "picoweb: --io_uring and --dpdk are mutually exclusive\n");
                return 1;
            }
            backend = PICOWEB_BACKEND_URING;
            continue;
        }
        if (strcmp(argv[i], "--dpdk") == 0) {
            if (backend != PICOWEB_BACKEND_EPOLL) {
                fprintf(stderr, "picoweb: --io_uring and --dpdk are mutually exclusive\n");
                return 1;
            }
            backend = PICOWEB_BACKEND_DPDK;
            continue;
        }
        if (strcmp(argv[i], "--sqpoll") == 0) {
            sqpoll = true;
            continue;
        }
        if (strncmp(argv[i], "--sqpoll-cpu=", 13) == 0) {
            char* end = NULL;
            long c = strtol(argv[i] + 13, &end, 10);
            if (end == argv[i] + 13 || *end != '\0' || c < 0 || c > 1023) {
                fprintf(stderr, "picoweb: invalid --sqpoll-cpu value\n");
                return 1;
            }
            sqpoll = true;
            sqpoll_cpu = (int)c;
            continue;
        }
        if (npos < (int)(sizeof(pos)/sizeof(pos[0]))) {
            pos[npos++] = argv[i];
        } else {
            fprintf(stderr, "picoweb: too many positional arguments\n");
            usage(argv[0]); return 1;
        }
    }

    if (npos > 0) {
        char* end = NULL;
        long p = strtol(pos[0], &end, 10);
        if (end == pos[0] || *end != '\0' || p < 1 || p > 65535) {
            usage(argv[0]); return 1;
        }
        port = (int)p;
    }
    if (npos > 1) wwwroot = pos[1];
    if (npos > 2) {
        char* end = NULL;
        long w = strtol(pos[2], &end, 10);
        if (end == pos[2] || *end != '\0' || w < 1 || w > 1024) {
            usage(argv[0]); return 1;
        }
        workers = w;
    }
    if (npos > 3) {
        char* end = NULL;
        long m = strtol(pos[3], &end, 10);
        if (end == pos[3] || *end != '\0' || m < 0 || m > 1000000) {
            usage(argv[0]); return 1;
        }
        max_reqs = m;
    }
    if (npos > 4) {
        char* end = NULL;
        long z = strtol(pos[4], &end, 10);
        if (end == pos[4] || *end != '\0' || z < 0 || z > (long)(64*1024*1024)) {
            usage(argv[0]); return 1;
        }
        zc_min = z;
    }
    if (npos > 5) {
        char* end = NULL;
        long pc = strtol(pos[5], &end, 10);
        if (end == pos[5] || *end != '\0' || pc < 1 || pc > 65536) {
            usage(argv[0]); return 1;
        }
        pool_cap = pc;
    }

    if (sqpoll && backend != PICOWEB_BACKEND_URING) {
        fprintf(stderr, "picoweb: --sqpoll requires --io_uring\n");
        return 1;
    }

    /* Reject --dpdk early — before spawning workers and binding ports
     * — so operators get a clean error instead of partially-started
     * workers all printing the stub message. */
    if (backend == PICOWEB_BACKEND_DPDK) {
        fprintf(stderr,
            "picoweb: --dpdk backend is not built into this binary.\n"
            "         See userspace/DESIGN.md for the integration plan.\n"
            "         The flag is reserved; running with it now is a\n"
            "         hard fail rather than a silent fallback.\n");
        return 2;
    }

    /* Pick the worker entrypoint up-front so each worker is launched
     * with the right loop. */
    void* (*worker_fn)(void*) = NULL;
    const char* backend_name = NULL;
    switch (backend) {
    case PICOWEB_BACKEND_EPOLL: worker_fn = epoll_worker_main; backend_name = "epoll"; break;
    case PICOWEB_BACKEND_URING: worker_fn = uring_worker_main; backend_name = "io_uring"; break;
    case PICOWEB_BACKEND_DPDK:  worker_fn = dpdk_worker_main;  backend_name = "dpdk";  break;
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
        cfgs[i].pool_cap              = (size_t)pool_cap;
        cfgs[i].idle_ms               = 10000;  /* 10s any-inactivity cap */
        cfgs[i].max_requests_per_conn = (uint32_t)max_reqs;
        cfgs[i].worker_index          = (int)i;
        cfgs[i].zerocopy_threshold    = (size_t)zc_min;
        cfgs[i].sqpoll                = sqpoll;
        /* SQPOLL kernel-thread CPU policy: avoid pinning the kernel
         * polling thread to the same core as its userspace worker
         * (worker i is pinned to (i % nproc)) — they'd thrash one
         * core's L1.
         *
         *   --sqpoll alone (no cpu arg): kernel chooses any CPU
         *      (passes -1 → no SQ_AFF). Best for general use.
         *
         *   --sqpoll-cpu=N: pin worker i's SQPOLL thread to
         *      ((N + i) mod nproc). N=workers (or N=nproc/2) puts
         *      the kernel threads on a disjoint core set from the
         *      workers when nproc >= 2 * workers. */
        if (sqpoll && sqpoll_cpu >= 0) {
            long nproc = sysconf(_SC_NPROCESSORS_ONLN);
            cfgs[i].sqpoll_cpu = (int)((sqpoll_cpu + i) % (nproc > 0 ? nproc : 1));
        } else {
            cfgs[i].sqpoll_cpu = -1;
        }
        if (pthread_create(&threads[i], NULL, worker_fn, &cfgs[i]) != 0) {
            metal_die("pthread_create #%ld", i);
        }
        /* Pin worker N to core (N % nproc). With SO_REUSEPORT each
         * worker has its own listen socket and per-worker state, so
         * keeping each on a fixed core preserves L1/L2 cache locality
         * and matches the kernel's RPS hashing for steady throughput.
         * Best-effort: failure is logged and ignored. */
#ifdef __linux__
        long nproc = sysconf(_SC_NPROCESSORS_ONLN);
        if (nproc >= 1) {
            cpu_set_t cpus;
            CPU_ZERO(&cpus);
            CPU_SET((int)(i % nproc), &cpus);
            if (pthread_setaffinity_np(threads[i], sizeof(cpus), &cpus) != 0) {
                metal_log("pthread_setaffinity_np worker %ld -> cpu %ld: %s",
                          i, i % nproc, strerror(errno));
            }
        }
#endif
    }

    /* Background thread that rebuilds the /stats body once per second. */
    metrics_start_updater();

    metal_log("picoweb: %ld worker(s) on :%d, root=%s, maxreqs=%ld, "
              "pool=%ld, backend=%s, zerocopy=%s, simd=%s",
              workers, port, wwwroot, max_reqs, pool_cap, backend_name,
              zc_min > 0 ? "on" : "off", metal_simd_describe());
    if (zc_min > 0) {
        metal_log("picoweb: MSG_ZEROCOPY threshold = %ld bytes", zc_min);
    }

    for (long i = 0; i < workers; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
