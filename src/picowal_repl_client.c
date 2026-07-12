/* picowal_repl_client.c — replica-side puller: a minimal blocking
 * HTTP/1.1 client (plain TCP, no TLS) purpose-built for polling
 * picowal_repl.c's primary feed from a background thread. This is a
 * control-plane concern, not on picoweb's hot request path, so a simple
 * blocking implementation is the right tradeoff here. */

#include "picowal_repl_client.h"
#include "api.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define REPL_HOST_MAX   256
#define REPL_PATH_MAX   256
#define REPL_TOKEN_MAX  128
#define REPL_POLL_IDLE_MS   250   /* sleep between polls once caught up */
#define REPL_RETRY_MS       2000  /* sleep after a connect/parse/timeout failure */
#define REPL_RESP_HEAD_MAX  4096  /* status line + headers */
#define REPL_CONNECT_TIMEOUT_MS  5000  /* bound TCP handshake against a
                                          black-holed/firewalled primary */
#define REPL_IO_TIMEOUT_MS       10000 /* bound each send()/recv() against a
                                          primary that accepts but never
                                          responds (or stalls mid-response) --
                                          without this a single unresponsive
                                          primary wedges the poller thread
                                          forever with no retry/log/recovery */

#define REPL_HEALTH_FAIL_THRESHOLD 3  /* consecutive failed status polls
                                          before the primary is considered
                                          unhealthy (used by picowal_gossip
                                          to trigger leader election) */

typedef struct {
    char host[REPL_HOST_MAX];
    int  port;
    char path_prefix[REPL_PATH_MAX]; /* e.g. "/repl/" */
    char token[REPL_TOKEN_MAX];
    picowal_db_t* db;
} repl_client_ctx_t;

static bool g_replica_mode = false;
static volatile int g_consecutive_failures = 0;
static volatile bool g_stop_requested = false;

bool picowal_replica_mode_enabled(void) { return g_replica_mode; }

bool picowal_repl_client_primary_healthy(void) {
    /* Not running as a replica at all (e.g. we are the primary, or we've
     * already been promoted) -- nothing to report as unhealthy. */
    if (!g_replica_mode) return true;
    return g_consecutive_failures < REPL_HEALTH_FAIL_THRESHOLD;
}

void picowal_repl_client_stop(void) {
    g_stop_requested = true;
}

/* Parses "http://host[:port]/path/" into host/port/path_prefix. Rejects
 * https:// outright (no TLS client here) and requires a trailing '/'. */
static bool parse_primary_url(const char* url, repl_client_ctx_t* ctx) {
    if (!url) return false;
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        fprintf(stderr, "picowal_repl_client: https:// primary URLs are not supported "
                "(no TLS client); terminate TLS in front of a plain-HTTP hop, or use a "
                "private network for replication traffic\n");
        return false;
    } else {
        fprintf(stderr, "picowal_repl_client: --picowal-replica-of must start with http://\n");
        return false;
    }

    const char* slash = strchr(p, '/');
    size_t hostport_len = slash ? (size_t)(slash - p) : strlen(p);
    if (hostport_len == 0 || hostport_len >= REPL_HOST_MAX) return false;

    char hostport[REPL_HOST_MAX];
    memcpy(hostport, p, hostport_len);
    hostport[hostport_len] = '\0';

    ctx->port = 80;
    char* colon = strrchr(hostport, ':');
    if (colon) {
        *colon = '\0';
        char* end = NULL;
        long v = strtol(colon + 1, &end, 10);
        if (end == colon + 1 || *end != '\0' || v <= 0 || v > 65535) return false;
        ctx->port = (int)v;
    }
    if (hostport[0] == '\0' || strlen(hostport) >= sizeof(ctx->host)) return false;
    memcpy(ctx->host, hostport, strlen(hostport) + 1);

    const char* path = slash ? slash : "/";
    size_t path_len = strlen(path);
    if (path_len == 0 || path_len >= sizeof(ctx->path_prefix)) return false;
    if (path[path_len - 1] != '/') {
        if (path_len + 1 >= sizeof(ctx->path_prefix)) return false;
        memcpy(ctx->path_prefix, path, path_len);
        ctx->path_prefix[path_len] = '/';
        ctx->path_prefix[path_len + 1] = '\0';
    } else {
        memcpy(ctx->path_prefix, path, path_len + 1);
    }
    return true;
}

/* Connects to ctx->host:ctx->port with a bounded timeout (non-blocking
 * connect + poll), then switches back to blocking mode with SO_RCVTIMEO/
 * SO_SNDTIMEO set so every subsequent send()/recv() is also bounded.
 * Returns a connected fd, or -1. */
static int repl_connect(const repl_client_ctx_t* ctx) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", ctx->port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(ctx->host, portstr, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo* a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int cr = connect(fd, a->ai_addr, a->ai_addrlen);
        if (cr == 0) {
            /* connected immediately (e.g. localhost) */
        } else if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, REPL_CONNECT_TIMEOUT_MS);
            int soerr = 0; socklen_t solen = sizeof(soerr);
            if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen) != 0 ||
                soerr != 0) {
                close(fd); fd = -1; continue;
            }
        } else {
            close(fd); fd = -1; continue;
        }

        if (flags >= 0) fcntl(fd, F_SETFL, flags); /* restore blocking mode */
        struct timeval tv;
        tv.tv_sec = REPL_IO_TIMEOUT_MS / 1000;
        tv.tv_usec = (REPL_IO_TIMEOUT_MS % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        break;
    }
    freeaddrinfo(res);
    return fd;
}

/* Issues a GET to path (relative to host root, already includes prefix),
 * reads the full response (status line + headers + body) into *out_body
 * (caller frees). Returns the HTTP status code, or -1 on transport/parse
 * failure. out_body/out_body_len describe the body only. */
static int repl_http_get(const repl_client_ctx_t* ctx, const char* path,
                         char** out_body, size_t* out_body_len) {
    *out_body = NULL;
    *out_body_len = 0;

    int fd = repl_connect(ctx);
    if (fd < 0) return -1;

    char req[REPL_PATH_MAX + REPL_TOKEN_MAX + 256];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "X-PW-Write-Token: %s\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     path, ctx->host, ctx->token);
    if (n <= 0 || (size_t)n >= sizeof(req)) { close(fd); return -1; }

    size_t sent = 0;
    while (sent < (size_t)n) {
        ssize_t w = send(fd, req + sent, (size_t)n - sent, 0);
        if (w < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        sent += (size_t)w;
    }

    /* Read the whole response (server sends Connection: close, so EOF
     * marks the end); bounded by a generous cap matching the largest
     * possible stream chunk plus headroom for headers. */
    size_t cap = REPL_RESP_HEAD_MAX + PICOWAL_REPL_CHUNK_MAX + 4096;
    char* buf = (char*)malloc(cap);
    if (!buf) { close(fd); return -1; }
    size_t got = 0;
    for (;;) {
        if (got >= cap) { free(buf); close(fd); return -1; } /* response too large */
        ssize_t r = recv(fd, buf + got, cap - got, 0);
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); return -1; }
        if (r == 0) break; /* EOF */
        got += (size_t)r;
    }
    close(fd);

    /* Parse "HTTP/1.1 NNN ...\r\n" then headers up to "\r\n\r\n". */
    if (got < 12 || strncmp(buf, "HTTP/1.", 7) != 0) { free(buf); return -1; }
    const char* sp = memchr(buf, ' ', got);
    if (!sp) { free(buf); return -1; }
    int status = (int)strtol(sp + 1, NULL, 10);
    if (status <= 0) { free(buf); return -1; }

    const char* hdr_end = NULL;
    for (size_t i = 0; i + 3 < got; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            hdr_end = buf + i + 4;
            break;
        }
    }
    if (!hdr_end) { free(buf); return -1; }

    size_t body_len = got - (size_t)(hdr_end - buf);
    if (body_len > 0) {
        char* body = (char*)malloc(body_len);
        if (!body) { free(buf); return -1; }
        memcpy(body, hdr_end, body_len);
        *out_body = body;
        *out_body_len = body_len;
    }
    free(buf);
    return status;
}

/* Extremely small-surface scan for `"key":NUMBER` in a flat JSON object
 * (the only shape /repl/status ever emits) -- avoids pulling in a JSON
 * parser for one integer field. */
static bool json_u64_field(const char* body, size_t body_len, const char* key, uint64_t* out) {
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen + 2 < body_len; i++) {
        if (body[i] == '"' && memcmp(body + i + 1, key, klen) == 0 &&
            body[i + 1 + klen] == '"') {
            size_t j = i + 2 + klen;
            while (j < body_len && (body[j] == ':' || body[j] == ' ')) j++;
            if (j >= body_len || body[j] < '0' || body[j] > '9') return false;
            uint64_t v = 0;
            while (j < body_len && body[j] >= '0' && body[j] <= '9') {
                v = v * 10 + (uint64_t)(body[j] - '0');
                j++;
            }
            *out = v;
            return true;
        }
    }
    return false;
}

static void* repl_client_thread(void* arg) {
    repl_client_ctx_t* ctx = (repl_client_ctx_t*)arg;
    char path[REPL_PATH_MAX + 32];

    for (;;) {
        if (g_stop_requested) {
            g_replica_mode = false;
            fprintf(stderr, "picowal_repl_client: stopped (promoted to writer)\n");
            free(ctx);
            return NULL;
        }
        snprintf(path, sizeof(path), "%sstatus", ctx->path_prefix);
        char* body = NULL; size_t body_len = 0;
        int status = repl_http_get(ctx, path, &body, &body_len);
        uint64_t remote_write_off = 0;
        bool have_status = (status == 200) && body &&
                            json_u64_field(body, body_len, "write_off", &remote_write_off);
        free(body);

        if (!have_status) {
            g_consecutive_failures++;
            fprintf(stderr, "picowal_repl_client: failed to reach primary status endpoint "
                    "(http status=%d); retrying in %dms (consecutive failures=%d)\n",
                    status, REPL_RETRY_MS, g_consecutive_failures);
            usleep(REPL_RETRY_MS * 1000);
            continue;
        }
        g_consecutive_failures = 0;

        uint64_t local_write_off = 0;
        picowal_db_repl_status(ctx->db, &local_write_off, NULL, NULL);

        bool made_progress = false;
        while (local_write_off < remote_write_off) {
            snprintf(path, sizeof(path), "%sstream/%llu", ctx->path_prefix,
                    (unsigned long long)local_write_off);
            char* chunk = NULL; size_t chunk_len = 0;
            int cs = repl_http_get(ctx, path, &chunk, &chunk_len);
            if (cs != 200) {
                fprintf(stderr, "picowal_repl_client: stream fetch failed (status=%d) "
                        "from offset %llu; retrying in %dms\n",
                        cs, (unsigned long long)local_write_off, REPL_RETRY_MS);
                free(chunk);
                usleep(REPL_RETRY_MS * 1000);
                break;
            }
            if (chunk_len == 0) { free(chunk); break; } /* caught up */
            if (picowal_db_repl_ingest(ctx->db, local_write_off, chunk, (uint32_t)chunk_len) != 0) {
                fprintf(stderr, "picowal_repl_client: ingest failed at offset %llu (%s); "
                        "retrying in %dms\n", (unsigned long long)local_write_off,
                        strerror(errno), REPL_RETRY_MS);
                free(chunk);
                usleep(REPL_RETRY_MS * 1000);
                break;
            }
            free(chunk);
            made_progress = true;
            picowal_db_repl_status(ctx->db, &local_write_off, NULL, NULL);
        }

        if (!made_progress) usleep(REPL_POLL_IDLE_MS * 1000);
    }
    return NULL;
}

bool picowal_repl_client_start(const char* primary_url, const char* write_token,
                               picowal_db_t* db) {
    if (!primary_url || !db) return false;
    if (!write_token || !write_token[0]) {
        fprintf(stderr, "picowal_repl_client: --picowal-replica-of requires "
                "--picowal-write-token/PICOWAL_WRITE_TOKEN to be set (must match the primary)\n");
        return false;
    }

    repl_client_ctx_t* ctx = (repl_client_ctx_t*)calloc(1, sizeof(*ctx));
    if (!ctx) return false;
    if (!parse_primary_url(primary_url, ctx)) {
        fprintf(stderr, "picowal_repl_client: invalid --picowal-replica-of URL '%s' "
                "(expected http://host[:port]/prefix/)\n", primary_url);
        free(ctx);
        return false;
    }
    if (strlen(write_token) >= sizeof(ctx->token)) {
        fprintf(stderr, "picowal_repl_client: write token too long\n");
        free(ctx);
        return false;
    }
    memcpy(ctx->token, write_token, strlen(write_token) + 1);
    ctx->db = db;

    pthread_t th;
    if (pthread_create(&th, NULL, repl_client_thread, ctx) != 0) {
        free(ctx);
        return false;
    }
    pthread_detach(th);
    g_replica_mode = true;
    fprintf(stderr, "picowal_repl_client: replicating from %s://%s:%d%s\n",
            "http", ctx->host, ctx->port, ctx->path_prefix);
    return true;
}
