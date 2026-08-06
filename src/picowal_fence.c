/*
 * picowal_fence.c — see picowal_fence.h.
 *
 * Fixed-frame Unix-socket client for picowald's data-fence check. The
 * wire constants below are a byte-for-byte copy of picowald's
 * include/fence_proto.h; picoweb keeps its own copy so this file stays
 * self-contained (no dependency on the picocluster source tree). Keep
 * the two in sync.
 */

#include "picowal_fence.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ---- wire protocol (mirror of picowald include/fence_proto.h) ---- */
#define PWFENCE_MAGIC        0x434E4546u   /* "FENC" LE */
#define PWFENCE_VERSION      1u
#define PWFENCE_OP_CHECK     1u
#define PWFENCE_GROUP_SZ     64u
#define PWFENCE_NODE_SZ      64u
#define PWFENCE_REQ_SIZE     (4u + 1u + 1u + 2u + 8u + PWFENCE_GROUP_SZ + PWFENCE_NODE_SZ)
#define PWFENCE_RESP_SIZE    (4u + 1u + 1u + 2u + 4u)
#define PWFENCE_OK           0u

#define PWFENCE_IO_TIMEOUT_SEC 2
/* Hard cap on the locally-cached lease. The control plane suggests a
 * lease (typically 500ms); we never trust anything above 1000ms and
 * clamp to this. Monotonic clock only. */
#define PWFENCE_CLIENT_LEASE_CAP_MS 500u

struct picowal_fence {
    char     sock_path[256];
    char     group[PWFENCE_GROUP_SZ];
    char     node[PWFENCE_NODE_SZ];
    uint64_t epoch;
    pthread_mutex_t mu;
    uint64_t lease_expiry_ms;   /* CLOCK_MONOTONIC; 0 = no valid lease */
};

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void wr32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF); p[3] = (uint8_t)((v >> 24) & 0xFF);
}
static void wr64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}
static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int write_all(int fd, const void* buf, size_t n) {
    const uint8_t* p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) { errno = EPIPE; return -1; }
        p += (size_t)w; n -= (size_t)w;
    }
    return 0;
}

static int read_all(int fd, void* buf, size_t n) {
    uint8_t* p = buf; size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) { errno = EIO; return -1; }
        got += (size_t)r;
    }
    return 0;
}

picowal_fence_t* picowal_fence_create(const char* sock_path, const char* group,
                                      uint64_t epoch, const char* node_id) {
    if (!sock_path || !sock_path[0] || !group || !group[0] ||
        !node_id || !node_id[0]) {
        errno = EINVAL;
        return NULL;
    }
    if (strlen(sock_path) >= sizeof(((picowal_fence_t*)0)->sock_path) ||
        strlen(group) >= PWFENCE_GROUP_SZ || strlen(node_id) >= PWFENCE_NODE_SZ) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    picowal_fence_t* f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    snprintf(f->sock_path, sizeof f->sock_path, "%s", sock_path);
    snprintf(f->group, sizeof f->group, "%s", group);
    snprintf(f->node, sizeof f->node, "%s", node_id);
    f->epoch = epoch;
    f->lease_expiry_ms = 0;
    if (pthread_mutex_init(&f->mu, NULL) != 0) { free(f); return NULL; }
    return f;
}

void picowal_fence_destroy(picowal_fence_t* f) {
    if (!f) return;
    pthread_mutex_destroy(&f->mu);
    free(f);
}

/* One request/response round-trip. Returns the status byte (>=0), or -1
 * on transport failure. On OK, *out_lease_ms carries the granted lease. */
static int do_check(picowal_fence_t* f, uint32_t* out_lease_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, f->sock_path, sizeof sa.sun_path - 1);
    struct timeval tv = { .tv_sec = PWFENCE_IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr*)&sa, sizeof sa) != 0) { close(fd); return -1; }

    uint8_t req[PWFENCE_REQ_SIZE];
    memset(req, 0, sizeof req);
    wr32(req, PWFENCE_MAGIC);
    req[4] = PWFENCE_VERSION;
    req[5] = PWFENCE_OP_CHECK;
    wr64(req + 8, f->epoch);
    memcpy(req + 16, f->group, strlen(f->group));
    memcpy(req + 16 + PWFENCE_GROUP_SZ, f->node, strlen(f->node));
    if (write_all(fd, req, sizeof req) != 0) { close(fd); return -1; }

    uint8_t resp[PWFENCE_RESP_SIZE];
    if (read_all(fd, resp, sizeof resp) != 0) { close(fd); return -1; }
    close(fd);
    if (rd32(resp) != PWFENCE_MAGIC || resp[4] != PWFENCE_VERSION) return -1;
    if (out_lease_ms) *out_lease_ms = rd32(resp + 8);
    return resp[5];
}

bool picowal_fence_check(picowal_fence_t* f) {
    if (!f) return false;
    pthread_mutex_lock(&f->mu);
    uint64_t now = mono_ms();
    if (f->lease_expiry_ms && now < f->lease_expiry_ms) {
        pthread_mutex_unlock(&f->mu);
        return true;   /* within a valid, quorum-issued lease */
    }
    uint32_t lease_ms = 0;
    int status = do_check(f, &lease_ms);
    bool ok = (status == (int)PWFENCE_OK);
    if (ok) {
        if (lease_ms > PWFENCE_CLIENT_LEASE_CAP_MS) lease_ms = PWFENCE_CLIENT_LEASE_CAP_MS;
        /* Re-read the clock after the (possibly slow) round-trip so the
         * lease window is measured from grant time, never overstated. */
        f->lease_expiry_ms = mono_ms() + lease_ms;
    } else {
        f->lease_expiry_ms = 0;   /* fail closed immediately */
    }
    pthread_mutex_unlock(&f->mu);
    return ok;
}

int picowal_fence_probe(picowal_fence_t* f) {
    if (!f) return -1;
    return do_check(f, NULL);
}
