#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include "jumptable.h"
#include "api.h"
#include "api_blob.h"
#include "static_pack.h"
#include "pico_route.h"
#include "metrics.h"
#include "server.h"
#include "simd.h"
#include "tls_certs.h"
#include "util.h"
#include "../userspace/crypto/ecdsa.h"

static void usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s [--io_uring | --dpdk | --tls] [--sqpoll [--sqpoll-cpu=N]] [--api-root=DIR [--api-prefix=/api/]] [--picowal-device=PATH [--picowal-prefix=/wal/] [--picowal-bytes=N] [--picowal-format] [--oidc-cookie-auth --oidc-cookie-ttl-sec=N --oidc-google-client-id=ID --oidc-entra-client-id=ID [--oidc-entra-tenant=TENANT]]] [--tls-cert=PATH --tls-key=PATH --tls-ifname=IFACE [--tls-peer-mac=MAC] [--tls-xdp [--tls-xdp-queue=N]]] [PORT] [WWWROOT] [WORKERS] [MAXREQS] [ZC_MIN] [POOL_CAP]\n"
        "\n"
        "  --io_uring   use the io_uring worker backend (Linux 5.6+, no liburing)\n"
        "  --dpdk       use the DPDK userspace backend (NOT BUILT — see\n"
        "               userspace/DESIGN.md; the flag is reserved and will\n"
        "               error out at startup until the integration ships)\n"
        "  --tls        use userspace TCP+TLS backend scaffold (AF_PACKET path;\n"
        "               requires --tls-ifname and cert/key resolution)\n"
        "  --tls-cert=PATH  TLS certificate PEM path (optional; if omitted\n"
        "                   picoweb searches /certs/tls.crt then ./certs/tls.crt)\n"
        "  --tls-key=PATH   TLS private key PEM path (optional; if omitted\n"
        "                   picoweb searches /certs/tls.key then ./certs/tls.key)\n"
        "  --tls-ifname=IFACE  interface for userspace packet I/O (required with --tls)\n"
        "  --tls-peer-mac=MAC  optional fixed L2 peer MAC hint for --tls\n"
        "  --tls-xdp           use AF_XDP socket I/O for --tls backend (copy mode)\n"
        "  --tls-xdp-queue=N   AF_XDP queue id (default 0)\n"
        "  --http-early-hints  enable HTTP/1.1 103 Early Hints with auto-derived\n"
        "                      Link: rel=preload headers (off by default)\n"
        "  --api-root=DIR      enable JSON CRUD API and store objects under DIR\n"
        "  --api-prefix=/p/    API route prefix (default /api/; must start/end '/')\n"
        "  --picowal-device=PATH  enable raw-volume picowal backend\n"
        "  --picowal-prefix=/p/   route prefix for picowal API (default /wal/)\n"
        "  --picowal-bytes=N      raw-volume size in bytes (default 1073741824)\n"
        "  --picowal-format       initialize/format picowal volume when missing\n"
        "  --blob-root=DIR      enable HTTPS-only content-addressed blob store under DIR\n"
        "                       (requires --tls --tls-cert=PATH --tls-key=PATH)\n"
        "  --blob-prefix=/p/    blob API route prefix (default /blob/)\n"
        "  --picowal-static-card=N  serve static content from picowal card N\n"
        "  --picowal-static-prefix=/p/  static-pack route prefix (default /site/)\n"
        "  --picowal-code-card=N    run PicoScript bytecode from picowal card N\n"
        "  --picowal-code-prefix=/p/   pico-route prefix (default /app/)\n"
        "  --picowal-write-token=TOK   shared secret for X-PW-Write-Token gating of\n"
        "                              raw static-pack/pico-route writes when OIDC\n"
        "                              auth is off (env PICOWAL_WRITE_TOKEN fallback;\n"
        "                              neither set -> such writes get 503)\n"
        "  --oidc-cookie-auth     require OIDC-backed short-lived cookie auth for /wal/ routes\n"
        "  --oidc-cookie-ttl-sec=N session cookie ttl in seconds (default 900)\n"
        "  --oidc-google-client-id=ID expected Google OAuth client id (aud)\n"
        "  --oidc-entra-client-id=ID expected Entra app client id (appid/aud)\n"
        "  --oidc-entra-tenant=T  optional Entra tenant id pin (tid)\n"
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
        "Default backend is epoll. --io_uring / --dpdk / --tls are mutually exclusive.\n",
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
    const char* tls_cert_cli = NULL;
    const char* tls_key_cli = NULL;
    const char* tls_ifname = NULL;
    const char* tls_peer_mac = NULL;
    bool tls_use_xdp = false;
    uint32_t tls_xdp_queue = 0;
    bool http_early_hints = false;
    const char* api_root_cli = NULL;
    const char* api_prefix_cli = "/api/";
    bool api_prefix_set = false;
    const char* picowal_device_cli = NULL;
    const char* picowal_prefix_cli = "/wal/";
    bool picowal_prefix_set = false;
    unsigned long long picowal_bytes = 1073741824ULL;
    bool picowal_format = false;
    const char* blob_root_cli = NULL;
    const char* blob_prefix_cli = "/blob/";
    bool blob_prefix_set = false;
    const char* static_pack_prefix_cli = "/site/";
    long static_pack_card = -1;   /* -1 = disabled */
    const char* pico_route_prefix_cli = "/app/";
    long pico_route_card = -1;    /* -1 = disabled */
    const char* picowal_write_token_cli = NULL;
    bool oidc_cookie_auth = false;
    uint32_t oidc_cookie_ttl_sec = 900;
    const char* oidc_google_client_id = NULL;
    const char* oidc_entra_client_id = NULL;
    const char* oidc_entra_tenant = NULL;

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
                fprintf(stderr, "picoweb: --io_uring / --dpdk / --tls are mutually exclusive\n");
                return 1;
            }
            backend = PICOWEB_BACKEND_URING;
            continue;
        }
        if (strcmp(argv[i], "--dpdk") == 0) {
            if (backend != PICOWEB_BACKEND_EPOLL) {
                fprintf(stderr, "picoweb: --io_uring / --dpdk / --tls are mutually exclusive\n");
                return 1;
            }
            backend = PICOWEB_BACKEND_DPDK;
            continue;
        }
        if (strcmp(argv[i], "--tls") == 0) {
            if (backend != PICOWEB_BACKEND_EPOLL) {
                fprintf(stderr, "picoweb: --io_uring / --dpdk / --tls are mutually exclusive\n");
                return 1;
            }
            backend = PICOWEB_BACKEND_TLS;
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
        if (strncmp(argv[i], "--tls-cert=", 11) == 0) {
            tls_cert_cli = argv[i] + 11;
            if (!tls_cert_cli[0]) {
                fprintf(stderr, "picoweb: --tls-cert requires a non-empty path\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--tls-key=", 10) == 0) {
            tls_key_cli = argv[i] + 10;
            if (!tls_key_cli[0]) {
                fprintf(stderr, "picoweb: --tls-key requires a non-empty path\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--tls-ifname=", 13) == 0) {
            tls_ifname = argv[i] + 13;
            if (!tls_ifname[0]) {
                fprintf(stderr, "picoweb: --tls-ifname requires a non-empty interface name\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--tls-peer-mac=", 15) == 0) {
            tls_peer_mac = argv[i] + 15;
            if (!tls_peer_mac[0]) {
                fprintf(stderr, "picoweb: --tls-peer-mac requires a non-empty MAC string\n");
                return 1;
            }
            continue;
        }
        if (strcmp(argv[i], "--tls-xdp") == 0) {
            tls_use_xdp = true;
            continue;
        }
        if (strcmp(argv[i], "--http-early-hints") == 0) {
            http_early_hints = true;
            continue;
        }
        if (strncmp(argv[i], "--api-root=", 11) == 0) {
            api_root_cli = argv[i] + 11;
            if (!api_root_cli[0]) {
                fprintf(stderr, "picoweb: --api-root requires a non-empty path\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--api-prefix=", 13) == 0) {
            api_prefix_cli = argv[i] + 13;
            api_prefix_set = true;
            if (!api_prefix_cli[0]) {
                fprintf(stderr, "picoweb: --api-prefix requires a non-empty prefix\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--picowal-device=", 17) == 0) {
            picowal_device_cli = argv[i] + 17;
            if (!picowal_device_cli[0]) {
                fprintf(stderr, "picoweb: --picowal-device requires a non-empty path\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--picowal-prefix=", 17) == 0) {
            picowal_prefix_cli = argv[i] + 17;
            picowal_prefix_set = true;
            if (!picowal_prefix_cli[0]) {
                fprintf(stderr, "picoweb: --picowal-prefix requires a non-empty prefix\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--picowal-bytes=", 16) == 0) {
            char* end = NULL;
            unsigned long long v = strtoull(argv[i] + 16, &end, 10);
            if (end == argv[i] + 16 || *end != '\0' || v < 4096ULL) {
                fprintf(stderr, "picoweb: invalid --picowal-bytes value\n");
                return 1;
            }
            picowal_bytes = v;
            continue;
        }
        if (strcmp(argv[i], "--picowal-format") == 0) {
            picowal_format = true;
            continue;
        }
        if (strncmp(argv[i], "--blob-root=", 12) == 0) {
            blob_root_cli = argv[i] + 12;
            if (!blob_root_cli[0]) {
                fprintf(stderr, "picoweb: --blob-root requires a non-empty path\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--blob-prefix=", 14) == 0) {
            blob_prefix_cli = argv[i] + 14;
            blob_prefix_set = true;
            if (!blob_prefix_cli[0]) {
                fprintf(stderr, "picoweb: --blob-prefix requires a non-empty prefix\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--picowal-static-card=", 22) == 0) {
            char* end = NULL;
            long v = strtol(argv[i] + 22, &end, 10);
            if (end == argv[i] + 22 || *end != '\0' || v < 0 || v > (long)PICOWAL_CARD_MAX) {
                fprintf(stderr, "picoweb: invalid --picowal-static-card value\n");
                return 1;
            }
            static_pack_card = v;
            continue;
        }
        if (strncmp(argv[i], "--picowal-static-prefix=", 24) == 0) {
            static_pack_prefix_cli = argv[i] + 24;
            if (!static_pack_prefix_cli[0]) {
                fprintf(stderr, "picoweb: --picowal-static-prefix requires a non-empty prefix\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--picowal-code-card=", 20) == 0) {
            char* end = NULL;
            long v = strtol(argv[i] + 20, &end, 10);
            if (end == argv[i] + 20 || *end != '\0' || v < 0 || v > (long)PICOWAL_CARD_MAX) {
                fprintf(stderr, "picoweb: invalid --picowal-code-card value\n");
                return 1;
            }
            pico_route_card = v;
            continue;
        }
        if (strncmp(argv[i], "--picowal-code-prefix=", 22) == 0) {
            pico_route_prefix_cli = argv[i] + 22;
            if (!pico_route_prefix_cli[0]) {
                fprintf(stderr, "picoweb: --picowal-code-prefix requires a non-empty prefix\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--picowal-write-token=", 22) == 0) {
            picowal_write_token_cli = argv[i] + 22;
            if (!picowal_write_token_cli[0]) {
                fprintf(stderr, "picoweb: --picowal-write-token requires a non-empty value\n");
                return 1;
            }
            continue;
        }
        if (strcmp(argv[i], "--oidc-cookie-auth") == 0) {
            oidc_cookie_auth = true;
            continue;
        }
        if (strncmp(argv[i], "--oidc-cookie-ttl-sec=", 22) == 0) {
            char* end = NULL;
            unsigned long v = strtoul(argv[i] + 22, &end, 10);
            if (end == argv[i] + 22 || *end != '\0' || v == 0 || v > 86400UL) {
                fprintf(stderr, "picoweb: invalid --oidc-cookie-ttl-sec value\n");
                return 1;
            }
            oidc_cookie_ttl_sec = (uint32_t)v;
            continue;
        }
        if (strncmp(argv[i], "--oidc-google-client-id=", 24) == 0) {
            oidc_google_client_id = argv[i] + 24;
            if (!oidc_google_client_id[0]) {
                fprintf(stderr, "picoweb: --oidc-google-client-id requires a non-empty value\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--oidc-entra-client-id=", 23) == 0) {
            oidc_entra_client_id = argv[i] + 23;
            if (!oidc_entra_client_id[0]) {
                fprintf(stderr, "picoweb: --oidc-entra-client-id requires a non-empty value\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--oidc-entra-tenant=", 20) == 0) {
            oidc_entra_tenant = argv[i] + 20;
            if (!oidc_entra_tenant[0]) {
                fprintf(stderr, "picoweb: --oidc-entra-tenant requires a non-empty value\n");
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "--tls-xdp-queue=", 16) == 0) {
            char* end = NULL;
            unsigned long q = strtoul(argv[i] + 16, &end, 10);
            if (end == argv[i] + 16 || *end != '\0' || q > 4096) {
                fprintf(stderr, "picoweb: invalid --tls-xdp-queue value\n");
                return 1;
            }
            tls_use_xdp = true;
            tls_xdp_queue = (uint32_t)q;
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
    if ((tls_cert_cli || tls_key_cli || tls_ifname || tls_peer_mac || tls_use_xdp) &&
        backend != PICOWEB_BACKEND_TLS) {
        fprintf(stderr, "picoweb: --tls-* flags require --tls\n");
        return 1;
    }
    if (api_prefix_set && !api_root_cli) {
        fprintf(stderr, "picoweb: --api-prefix requires --api-root\n");
        return 1;
    }
    if (picowal_prefix_set && !picowal_device_cli) {
        fprintf(stderr, "picoweb: --picowal-prefix requires --picowal-device\n");
        return 1;
    }
    if (picowal_format && !picowal_device_cli) {
        fprintf(stderr, "picoweb: --picowal-format requires --picowal-device\n");
        return 1;
    }
    if (oidc_cookie_auth && !picowal_device_cli) {
        fprintf(stderr, "picoweb: --oidc-cookie-auth requires --picowal-device\n");
        return 1;
    }
    if (!oidc_cookie_auth &&
        (oidc_google_client_id || oidc_entra_client_id || oidc_entra_tenant)) {
        fprintf(stderr, "picoweb: --oidc-* provider flags require --oidc-cookie-auth\n");
        return 1;
    }
    if (blob_prefix_set && !blob_root_cli) {
        fprintf(stderr, "picoweb: --blob-prefix requires --blob-root\n");
        return 1;
    }
    if (static_pack_card >= 0 && !picowal_device_cli) {
        fprintf(stderr, "picoweb: --picowal-static-card requires --picowal-device\n");
        return 1;
    }
    if (pico_route_card >= 0 && !picowal_device_cli) {
        fprintf(stderr, "picoweb: --picowal-code-card requires --picowal-device\n");
        return 1;
    }
    if (blob_root_cli &&
        (backend != PICOWEB_BACKEND_TLS || !tls_cert_cli || !tls_key_cli)) {
        fprintf(stderr,
            "picoweb: --blob-root requires HTTPS: pass --tls --tls-cert=PATH "
            "--tls-key=PATH --tls-ifname=IFACE (blob data is never served over "
            "plaintext HTTP)\n");
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

    if (api_root_cli) {
        api_init(api_root_cli, api_prefix_cli);
        if (!api_enabled()) {
            fprintf(stderr, "picoweb: failed to enable API (root='%s', prefix='%s')\n",
                    api_root_cli, api_prefix_cli);
            return 1;
        }
    }
    if (picowal_device_cli) {
        if (!api_picowal_init(picowal_device_cli, (uint64_t)picowal_bytes,
                              picowal_prefix_cli, picowal_format)) {
            return 1;
        }
        if (static_pack_card >= 0 || pico_route_card >= 0) {
            const char* token = picowal_write_token_cli;
            if (!token) token = getenv("PICOWAL_WRITE_TOKEN");
            if (token && token[0]) {
                api_set_write_token(token);
            } else {
                fprintf(stderr, "picoweb: warning: no --picowal-write-token/PICOWAL_WRITE_TOKEN set; "
                        "raw picowal PUT/DELETE writes will be refused (503) unless --oidc-cookie-auth is enabled\n");
            }
        }
        if (static_pack_card >= 0) {
            if (!static_pack_init((uint16_t)static_pack_card, static_pack_prefix_cli)) {
                fprintf(stderr, "picoweb: failed to enable static-pack routes "
                        "(card=%ld, prefix='%s')\n", static_pack_card, static_pack_prefix_cli);
                return 1;
            }
        }
        if (pico_route_card >= 0) {
            if (!pico_route_init((uint16_t)pico_route_card, pico_route_prefix_cli)) {
                fprintf(stderr, "picoweb: failed to enable pico-route routes "
                        "(card=%ld, prefix='%s')\n", pico_route_card, pico_route_prefix_cli);
                return 1;
            }
        }
    }
    if (blob_root_cli) {
        if (!api_blob_init(blob_root_cli, blob_prefix_cli)) {
            fprintf(stderr, "picoweb: failed to enable blob API (root='%s', prefix='%s')\n",
                    blob_root_cli, blob_prefix_cli);
            return 1;
        }
    }
    if (oidc_cookie_auth) {
        if (!api_oidc_init(true, oidc_cookie_ttl_sec,
                           oidc_google_client_id,
                           oidc_entra_client_id,
                           oidc_entra_tenant)) {
            return 1;
        }
    } else {
        (void)api_oidc_init(false, oidc_cookie_ttl_sec, NULL, NULL, NULL);
    }

    char tls_cert_path[PATH_MAX];
    char tls_key_path[PATH_MAX];
    tls_cert_path[0] = '\0';
    tls_key_path[0] = '\0';
    if (backend == PICOWEB_BACKEND_TLS) {
        if (tls_ifname && tls_ifname[0]) {
            fprintf(stderr,
                "picoweb: --tls-ifname is no longer used (the kernel-socket "
                "TLS server doesn't need a raw NIC). Ignoring.\n");
            tls_ifname = NULL;
        }
        if (tls_use_xdp) {
            fprintf(stderr,
                "picoweb: --tls-xdp is no longer used (AF_XDP path is "
                "preserved in legacy/, not built into this binary). Ignoring.\n");
            tls_use_xdp = false;
        }
        if (picoweb_tls_locate_certs(tls_cert_cli, tls_key_cli,
                                     tls_cert_path, tls_key_path,
                                     sizeof(tls_cert_path), NULL) != 0) {
            return 1;
        }
    }

    /* Pick the worker entrypoint up-front so each worker is launched
     * with the right loop. */
    void* (*worker_fn)(void*) = NULL;
    const char* backend_name = NULL;
    switch (backend) {
    case PICOWEB_BACKEND_EPOLL: worker_fn = epoll_worker_main; backend_name = "epoll"; break;
    case PICOWEB_BACKEND_URING: worker_fn = uring_worker_main; backend_name = "io_uring"; break;
    case PICOWEB_BACKEND_DPDK:  worker_fn = dpdk_worker_main;  backend_name = "dpdk";  break;
    case PICOWEB_BACKEND_TLS:   worker_fn = tls_worker_main;   backend_name = "tls";   break;
    }

    /* SIGPIPE: ignore so writes to a peer-closed socket return EPIPE
     * instead of killing the process. (We also pass MSG_NOSIGNAL on
     * sendmsg, so this is belt and braces.) */
    signal(SIGPIPE, SIG_IGN);

    /* Initialize per-worker metrics state. MUST happen before
     * jumptable_build (which calls metrics_build_resources for /stats). */
    metrics_init((int)workers);

    /* Spawn the ECDSA-P256 precompute pool + producer thread. Each
     * pooled tuple lets a TLS handshake skip the dominant k*G and
     * scalar_inv ops, dropping per-sign cost from ~5-50 ms to a few
     * mod-muls. Failure is non-fatal: sign() transparently falls back
     * to the inline RFC 6979 path. Only meaningful for the TLS
     * backend, but cheap enough to start unconditionally. */
    if (backend == PICOWEB_BACKEND_TLS) {
        if (ecdsa_p256_precomp_init(64) != 0) {
            metal_log("warning: ecdsa precompute pool init failed; "
                      "sign() will use inline path");
        } else {
            metal_log("ecdsa precompute pool: cap=64, producer thread started");
        }
    }

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
        cfgs[i].tls_cert_path         = tls_cert_path[0] ? tls_cert_path : NULL;
        cfgs[i].tls_key_path          = tls_key_path[0] ? tls_key_path : NULL;
        cfgs[i].tls_ifname            = tls_ifname;
        cfgs[i].tls_peer_mac          = tls_peer_mac;
        cfgs[i].tls_use_xdp           = tls_use_xdp;
        cfgs[i].tls_xdp_queue         = tls_xdp_queue;
        cfgs[i].http_early_hints      = http_early_hints;
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
        pthread_attr_t attr;
        pthread_attr_t* attr_p = NULL;
        if (backend == PICOWEB_BACKEND_TLS) {
            pthread_attr_init(&attr);
            pthread_attr_setstacksize(&attr, 2 * 1024 * 1024); /* 2MB for TLS ctx */
            attr_p = &attr;
        }
        if (pthread_create(&threads[i], attr_p, worker_fn, &cfgs[i]) != 0) {
            metal_die("pthread_create #%ld", i);
        }
        if (attr_p) pthread_attr_destroy(&attr);
        /* Pin worker N to a CPU. We deliberately AVOID CPU 0 when
         * possible because the veth NET_RX softirq for inbound traffic
         * tends to run on CPU 0 (it hashes the first interrupt-handling
         * core), and a busy-polling user thread on the same core fights
         * those softirqs for cycles — under burst load this manifests as
         * XDP-layer RX drops because softirq slice doesn't run long
         * enough to push frames into the XSK ring before the user thread
         * resumes.
         * Mapping: worker N -> CPU ((N + 1) % nproc). With workers=1 and
         * nproc>=2, that puts the worker on CPU 1 and leaves CPU 0 free
         * for kernel softirqs. With nproc==1 we have no choice and stay
         * on CPU 0. With workers>1 we still cycle across all cores.
         * Best-effort: failure is logged and ignored. */
#ifdef __linux__
        long nproc = sysconf(_SC_NPROCESSORS_ONLN);
        if (nproc >= 1) {
            long target = (nproc >= 2) ? ((i + 1) % nproc) : 0;
            cpu_set_t cpus;
            CPU_ZERO(&cpus);
            CPU_SET((int)target, &cpus);
            if (pthread_setaffinity_np(threads[i], sizeof(cpus), &cpus) != 0) {
                metal_log("pthread_setaffinity_np worker %ld -> cpu %ld: %s",
                          i, target, strerror(errno));
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
    if (api_enabled()) {
        metal_log("picoweb: API enabled (root=%s, prefix=%s)", api_root_cli, api_prefix_cli);
    }
    if (api_picowal_enabled()) {
        metal_log("picoweb: picowal enabled (device=%s, prefix=%s, bytes=%llu)",
                  picowal_device_cli, picowal_prefix_cli, picowal_bytes);
    }
    if (api_blob_enabled()) {
        metal_log("picoweb: blob store enabled over HTTPS (root=%s, prefix=%s)",
                  blob_root_cli, blob_prefix_cli);
    }
    if (oidc_cookie_auth) {
        metal_log("picoweb: OIDC cookie auth enabled (ttl=%us, providers=google+entra)",
                  oidc_cookie_ttl_sec);
    }

    for (long i = 0; i < workers; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
