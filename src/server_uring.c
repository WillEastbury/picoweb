/*
 * picoweb io_uring worker — alternative backend to server.c.
 *
 *   Selected at build time via `make uring` which produces the binary
 *   `picoweb_uring`. The epoll worker (server.c) is excluded from that
 *   build via a Makefile filter; only one backend is linked at a time
 *   so uring_worker_main has a single definition.
 *
 *   No third-party libraries: this file talks to io_uring via raw
 *   syscalls (io_uring_setup / io_uring_enter), the kernel-provided
 *   <linux/io_uring.h>, and a small SQE/CQE ring abstraction we
 *   maintain ourselves. liburing is NOT used — keeps the dependency
 *   surface identical to the epoll backend.
 *
 * Op model (one ring per worker; user_data packs op-tag + conn index):
 *
 *   accept(listen_fd)        -> CQE with the new client fd
 *   recv(client_fd, buf)     -> CQE with bytes read
 *   sendmsg(client_fd, iov)  -> CQE with bytes sent (partial-send loop)
 *   close(client_fd)         -> CQE drives slot return
 *   timeout                  -> per-conn idle deadline (linked to recv)
 *
 * Same business logic as the epoll worker:
 *   - http_parse → http_select → swap to compressed variant if accepted
 *   - sendmsg with up to METAL_MAX_SEGS iovecs (head + conn_tail +
 *     chrome.hdr + body + chrome.ftr) which collapses to (head + conn_tail
 *     + body_br) when serving the precomputed compressed variant.
 *
 * What's NOT in the spike (call out in README):
 *   - Multishot accept / recv (works on 5.19+; we use one-shot for
 *     compatibility with the WSL2 5.15 kernel)
 *   - Registered fds / fixed buffers (next-level perf; design intact)
 *
 * Zero-copy send (Linux 6.0+):
 *   When `cfg->zerocopy_threshold` is non-zero, sends whose total
 *   payload meets the threshold use IORING_OP_SENDMSG_ZC instead of
 *   IORING_OP_SENDMSG. Response bytes live forever in the immutable
 *   arena, so the F_NOTIF "kernel done with buffer" CQE is just
 *   consumed and ignored. On kernels older than 6.0 the first ZC
 *   send returns -EINVAL/-EOPNOTSUPP; the worker logs once, sets
 *   the threshold to 0, and resubmits the same payload as a plain
 *   SENDMSG so the response still goes out.
 */

#include "server.h"

#include "http.h"
#include "jumptable.h"
#include "metrics.h"
#include "mime.h"
#include "pool.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* ============================================================== */
/* Module state shared with the rest of the program.              */
/* ============================================================== */

/* g_metrics, g_n_workers, g_worker_metrics live in metrics.c — same
 * setup as the epoll backend. The jumptable is reached via cfg->jt. */
extern metrics_t* g_metrics;
extern int        g_n_workers;
extern __thread metrics_t* g_worker_metrics;

/* Shared connection-tail segments — same as server.c. */
static const char CONN_KA[]    = "\r\n";
static const char CONN_CLOSE[] = "Connection: close\r\n\r\n";
#define CONN_KA_LEN    (sizeof(CONN_KA) - 1)
#define CONN_CLOSE_LEN (sizeof(CONN_CLOSE) - 1)

/* ============================================================== */
/* Raw io_uring syscalls.                                         */
/* ============================================================== */

static inline int io_uring_setup(unsigned entries, struct io_uring_params* p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                                 unsigned flags, sigset_t* sig) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
                        flags, sig, _NSIG / 8);
}

/* ============================================================== */
/* Ring layout. We mmap the SQ ring, the CQ ring, and the SQE     */
/* array per the kernel-described offsets in io_uring_params.     */
/* ============================================================== */

typedef struct {
    int fd;

    /* Submission ring */
    unsigned*  sq_head;
    unsigned*  sq_tail;
    unsigned   sq_ring_mask;
    unsigned   sq_ring_entries;
    unsigned*  sq_array;
    void*      sq_ring_ptr;
    size_t     sq_ring_sz;

    /* Submission entries */
    struct io_uring_sqe* sqes;
    size_t     sqes_sz;

    /* Completion ring */
    unsigned*  cq_head;
    unsigned*  cq_tail;
    unsigned   cq_ring_mask;
    unsigned   cq_ring_entries;
    struct io_uring_cqe* cqes;
    void*      cq_ring_ptr;
    size_t     cq_ring_sz;
} ring_t;

static bool ring_init(ring_t* r, unsigned entries) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    int fd = io_uring_setup(entries, &p);
    if (fd < 0) {
        metal_log("io_uring_setup(%u) failed: %s", entries, strerror(errno));
        return false;
    }
    memset(r, 0, sizeof(*r));
    r->fd = fd;

    r->sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    r->cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

    /* Single-mmap optimisation (IORING_FEAT_SINGLE_MMAP, kernel 5.4+):
     * SQ + CQ share one mapping. Use the larger of the two sizes. */
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (r->cq_ring_sz > r->sq_ring_sz) r->sq_ring_sz = r->cq_ring_sz;
        r->cq_ring_sz = r->sq_ring_sz;
    }

    r->sq_ring_ptr = mmap(NULL, r->sq_ring_sz,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (r->sq_ring_ptr == MAP_FAILED) {
        metal_log("io_uring SQ ring mmap failed: %s", strerror(errno));
        close(fd); return false;
    }
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        r->cq_ring_ptr = r->sq_ring_ptr;
    } else {
        r->cq_ring_ptr = mmap(NULL, r->cq_ring_sz,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
        if (r->cq_ring_ptr == MAP_FAILED) {
            metal_log("io_uring CQ ring mmap failed: %s", strerror(errno));
            munmap(r->sq_ring_ptr, r->sq_ring_sz);
            close(fd); return false;
        }
    }

    r->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) {
        metal_log("io_uring SQEs mmap failed: %s", strerror(errno));
        return false;
    }

    /* Pin pointers into the SQ ring buffer at the offsets the kernel
     * gave us. From here on we treat them like a fixed-size SPMC ring. */
    r->sq_head        = (unsigned*)((char*)r->sq_ring_ptr + p.sq_off.head);
    r->sq_tail        = (unsigned*)((char*)r->sq_ring_ptr + p.sq_off.tail);
    r->sq_ring_mask   = *(unsigned*)((char*)r->sq_ring_ptr + p.sq_off.ring_mask);
    r->sq_ring_entries= *(unsigned*)((char*)r->sq_ring_ptr + p.sq_off.ring_entries);
    r->sq_array       = (unsigned*)((char*)r->sq_ring_ptr + p.sq_off.array);

    r->cq_head        = (unsigned*)((char*)r->cq_ring_ptr + p.cq_off.head);
    r->cq_tail        = (unsigned*)((char*)r->cq_ring_ptr + p.cq_off.tail);
    r->cq_ring_mask   = *(unsigned*)((char*)r->cq_ring_ptr + p.cq_off.ring_mask);
    r->cq_ring_entries= *(unsigned*)((char*)r->cq_ring_ptr + p.cq_off.ring_entries);
    r->cqes           = (struct io_uring_cqe*)((char*)r->cq_ring_ptr + p.cq_off.cqes);

    return true;
}

/* SPSC SQE handout. Returns NULL if the SQ is full — caller must
 * io_uring_enter to drain. The acquire/release pattern here matches
 * the kernel's published memory-order rules. */
static struct io_uring_sqe* ring_get_sqe(ring_t* r) {
    unsigned head = atomic_load_explicit((_Atomic unsigned*)r->sq_head,
                                         memory_order_acquire);
    unsigned tail = *r->sq_tail;
    if (tail - head >= r->sq_ring_entries) return NULL;
    unsigned idx = tail & r->sq_ring_mask;
    return &r->sqes[idx];
}

/* Publish the SQE we just filled. */
static void ring_publish(ring_t* r) {
    unsigned tail = *r->sq_tail;
    unsigned idx  = tail & r->sq_ring_mask;
    r->sq_array[idx] = idx;
    atomic_store_explicit((_Atomic unsigned*)r->sq_tail, tail + 1,
                          memory_order_release);
}

/* IORING_OP_SENDMSG_ZC was added in Linux 6.0; CQE flag F_NOTIF
 * (bit 3) signals "kernel done with the buffer" for zero-copy
 * sends. Provide fallback defines so older headers still compile;
 * runtime kernels older than 6.0 will simply fail the op with
 * -EINVAL on the first attempt and the caller leaves zerocopy
 * disabled. */
#ifndef IORING_OP_SENDMSG_ZC
#  define IORING_OP_SENDMSG_ZC 49
#endif
#ifndef IORING_CQE_F_NOTIF
#  define IORING_CQE_F_NOTIF (1U << 3)
#endif
#ifndef IORING_CQE_F_MORE
#  define IORING_CQE_F_MORE  (1U << 1)
#endif

/* Per-worker MSG_ZEROCOPY threshold. 0 = SENDMSG always; >0 means
 * use IORING_OP_SENDMSG_ZC for any response payload of at least
 * this many bytes. Set once before the worker loop runs. */
static __thread size_t g_uring_zc_threshold = 0;

/* ============================================================== */
/*                                                                */
/* Bits:  56..63  op tag                                          */
/*         0..55  conn index in the pool (or 0 for accept)        */
/* ============================================================== */

#define OP_ACCEPT 1
#define OP_RECV   2
#define OP_SEND   3
#define OP_CLOSE  4

static inline uint64_t pack_ud(uint8_t op, uint64_t idx) {
    return ((uint64_t)op << 56) | (idx & 0x00ffffffffffffffULL);
}
static inline uint8_t  ud_op(uint64_t ud)  { return (uint8_t)(ud >> 56); }
static inline uint64_t ud_idx(uint64_t ud) { return ud & 0x00ffffffffffffffULL; }

/* ============================================================== */
/* Per-conn extra state for io_uring.                             */
/*                                                                */
/* sendmsg requires the iovec + msghdr to live until the kernel   */
/* finishes the op — so we keep them in the conn slot itself.    */
/* The pool_t / conn_t already provides one cache-line-aligned    */
/* slot per connection; we hang a small uring_state_t off it via  */
/* an index lookup. Sized to match the pool. */
/* ============================================================== */

typedef struct {
    struct iovec  iov[METAL_MAX_SEGS];
    struct msghdr mh;
    uint8_t       in_flight;     /* OP_* of the current submitted op (0 = none) */
    uint8_t       last_was_zc;   /* did the most recent send use SENDMSG_ZC?    */
} uring_state_t;

static uring_state_t* g_uring_state = NULL;
static size_t         g_uring_state_n = 0;

/* ============================================================== */
/* Op submitters.                                                 */
/* ============================================================== */

static bool submit_accept(ring_t* r, int listen_fd) {
    struct io_uring_sqe* sqe = ring_get_sqe(r);
    if (!sqe) return false;
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_ACCEPT;
    sqe->fd        = listen_fd;
    sqe->addr      = 0;
    sqe->addr2     = 0;   /* we don't need the peer's sockaddr */
    sqe->user_data = pack_ud(OP_ACCEPT, 0);
    ring_publish(r);
    return true;
}

static bool submit_recv(ring_t* r, conn_t* c, size_t conn_idx) {
    struct io_uring_sqe* sqe = ring_get_sqe(r);
    if (!sqe) return false;
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_RECV;
    sqe->fd        = c->fd;
    sqe->addr      = (uint64_t)(uintptr_t)(c->read_buf + c->read_off);
    sqe->len       = (uint32_t)(METAL_READ_BUF - c->read_off);
    sqe->user_data = pack_ud(OP_RECV, conn_idx);
    ring_publish(r);
    g_uring_state[conn_idx].in_flight = OP_RECV;
    return true;
}

static bool submit_close(ring_t* r, int fd, size_t conn_idx) {
    struct io_uring_sqe* sqe = ring_get_sqe(r);
    if (!sqe) return false;
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_CLOSE;
    sqe->fd        = fd;
    sqe->user_data = pack_ud(OP_CLOSE, conn_idx);
    ring_publish(r);
    return true;
}

/* Build the iovec for the current response and submit a sendmsg op.
 * Walks the segment list against c->bytes_sent to compute the partial-
 * send tail — the kernel will keep going from where we left off.
 *
 * If `total_payload` is at least g_uring_zc_threshold (and threshold
 * is non-zero), the op uses IORING_OP_SENDMSG_ZC. The response
 * payload bytes are owned by the immutable arena and live forever,
 * so we don't need to track buffer-release notifications — we just
 * ignore the extra IORING_CQE_F_NOTIF cqe in the OP_SEND handler. */
static bool submit_sendmsg(ring_t* r, conn_t* c, size_t conn_idx,
                           size_t total_payload) {
    uring_state_t* us = &g_uring_state[conn_idx];

    /* Build iovec from conn_t segments, skipping past bytes_sent. */
    int n = 0;
    size_t skip = c->bytes_sent;
    for (int i = 0; i < c->seg_count; i++) {
        if (skip >= c->segs[i].len) {
            skip -= c->segs[i].len;
            continue;
        }
        us->iov[n].iov_base = (void*)(c->segs[i].ptr + skip);
        us->iov[n].iov_len = c->segs[i].len - skip;
        skip = 0;
        n++;
    }
    if (n == 0) return false;
    memset(&us->mh, 0, sizeof(us->mh));
    us->mh.msg_iov    = us->iov;
    us->mh.msg_iovlen = (size_t)n;

    struct io_uring_sqe* sqe = ring_get_sqe(r);
    if (!sqe) return false;
    memset(sqe, 0, sizeof(*sqe));
    int use_zc = (g_uring_zc_threshold > 0
                  && total_payload >= g_uring_zc_threshold);
    sqe->opcode    = use_zc ? IORING_OP_SENDMSG_ZC : IORING_OP_SENDMSG;
    sqe->fd        = c->fd;
    sqe->addr      = (uint64_t)(uintptr_t)&us->mh;
    sqe->msg_flags = MSG_NOSIGNAL;
    sqe->user_data = pack_ud(OP_SEND, conn_idx);
    ring_publish(r);
    us->in_flight   = OP_SEND;
    us->last_was_zc = (uint8_t)use_zc;
    return true;
}

/* ============================================================== */
/* Connection lifecycle helpers (mirror server.c semantics).      */
/* ============================================================== */

static void conn_reset_for_next(conn_t* c) {
    c->res         = NULL;
    c->seg_count   = 0;
    c->bytes_sent  = 0;
    c->wire_total  = 0;
    c->send_body   = false;
    c->active_variant = NULL;
    c->state       = ST_READING;
    c->last_active_ms = metal_now_ms_coarse();
}

static void conn_init_new(conn_t* c, int fd) {
    c->fd = fd;
    c->state = ST_READING;
    c->read_off = 0;
    c->res = NULL;
    c->seg_count = 0;
    c->send_body = false;
    c->active_variant = NULL;
    c->wire_total = 0;
    c->bytes_sent = 0;
    c->close_after = false;
    c->req_count = 0;
    c->peer_half_closed = false;
    c->req_start_tsc = 0;
    c->last_active_ms = metal_now_ms_coarse();
    c->epoll_mask = 0;
}

/* Compute the wire-bytes total for the response c is currently
 * serving — head + (chrome.hdr + body + chrome.ftr) for uncompressed,
 * or (head + body) for the precomputed compressed variant. Used both
 * to detect "send done" and to pick SENDMSG vs SENDMSG_ZC. */
static inline size_t conn_total_payload(const conn_t* c) {
    return c->wire_total;
}

/* Apply parser result + dispatch a response. Returns true on success
 * (caller should submit_sendmsg), false to close. */
static bool dispatch_one(conn_t* c, const jumptable_t* jt, uint32_t max_req) {
    http_request_t req;
    http_result_t pr = http_parse(c->read_buf, c->read_off, &req);
    if (pr == HTTP_NEED_MORE) return true;   /* waits for next recv */

    c->req_start_tsc = metal_tsc();

    bool close_after, head_only;
    const resource_t* r = http_select(jt, pr, &req, &close_after, &head_only);

    c->req_count++;
    if (max_req && c->req_count >= max_req) close_after = true;

    c->res = r;
    const resource_compress_t* variant = NULL;
    if (req.accept_br && r->brotli != NULL)
        variant = r->brotli;
    else if (req.accept_pc && r->compressed != NULL)
        variant = r->compressed;

    c->active_variant = variant;

    /* Build iovec segments — same logic as epoll backend.
     * head + conn_tail + body pieces. */
    {
        const char* head = variant ? variant->head : r->head;
        size_t head_len  = variant ? variant->head_len : r->head_len;

        int ns = 0;
        c->segs[ns].ptr = head;
        c->segs[ns].len = head_len;
        ns++;

        c->segs[ns].ptr = close_after ? CONN_CLOSE : CONN_KA;
        c->segs[ns].len = close_after ? CONN_CLOSE_LEN : CONN_KA_LEN;
        ns++;

        if (!head_only) {
            if (variant) {
                c->segs[ns].ptr = variant->body;
                c->segs[ns].len = variant->body_len;
                ns++;
            } else {
                if (r->chrome && r->chrome->hdr_len) {
                    c->segs[ns].ptr = r->chrome->hdr;
                    c->segs[ns].len = r->chrome->hdr_len;
                    ns++;
                }
                if (r->body_len) {
                    c->segs[ns].ptr = r->body;
                    c->segs[ns].len = r->body_len;
                    ns++;
                }
                if (r->chrome && r->chrome->ftr_len) {
                    c->segs[ns].ptr = r->chrome->ftr;
                    c->segs[ns].len = r->chrome->ftr_len;
                    ns++;
                }
            }
        }

        c->seg_count = (uint8_t)ns;
        size_t total = 0;
        for (int i = 0; i < ns; i++) total += c->segs[i].len;
        c->wire_total = total;
    }

    /* ETag / 304 Not Modified — same logic as epoll backend. */
    if (pr == HTTP_OK && req.if_none_match &&
        (req.method == M_GET || req.method == M_HEAD)) {
        const char* etag;
        const char* w304;
        size_t w304_len;
        if (variant) {
            etag = variant->etag;
            w304 = variant->wire_304;
            w304_len = variant->wire_304_len;
        } else if (r->etag[0] != '\0') {
            etag = r->etag;
            w304 = r->wire_304;
            w304_len = r->wire_304_len;
        } else {
            etag = NULL; w304 = NULL; w304_len = 0;
        }
        if (etag && w304 && etag_matches(req.if_none_match,
                                          req.if_none_match_len, etag)) {
            c->segs[0].ptr = w304;
            c->segs[0].len = w304_len;
            c->segs[1].ptr = close_after ? CONN_CLOSE : CONN_KA;
            c->segs[1].len = close_after ? CONN_CLOSE_LEN : CONN_KA_LEN;
            c->seg_count = 2;
            c->wire_total = w304_len + c->segs[1].len;
            head_only = true;
        }
    }

    c->send_body  = !head_only;
    c->bytes_sent = 0;
    c->close_after = close_after;
    c->state = ST_WRITING;

    /* Compact buffer for next request. */
    if (pr == HTTP_OK && req.consumed > 0 && c->read_off > req.consumed) {
        size_t leftover = c->read_off - req.consumed;
        memmove(c->read_buf, c->read_buf + req.consumed, leftover);
        c->read_off = leftover;
    } else {
        c->read_off = 0;
    }
    return true;
}

/* ============================================================== */
/* Worker entry point — symbol shared with the epoll backend.     */
/* ============================================================== */

void* uring_worker_main(void* arg) {
    server_cfg_t* cfg = (server_cfg_t*)arg;

    if (g_metrics && cfg->worker_index >= 0 && cfg->worker_index < g_n_workers) {
        g_worker_metrics = &g_metrics[cfg->worker_index];
    }

    /* Pick up the MSG_ZEROCOPY threshold for this worker. 0 means
     * always use plain SENDMSG; >0 means switch to SENDMSG_ZC for
     * any payload at or above the threshold. Same env knob as the
     * epoll backend (cfg->zerocopy_threshold). */
    g_uring_zc_threshold = cfg->zerocopy_threshold;

    /* TCP listener — same SO_REUSEPORT pattern as the epoll backend
     * so multiple workers genuinely share load. */
    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (lfd < 0) metal_die("socket: %s", strerror(errno));
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
    setsockopt(lfd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    struct sockaddr_in sa = { .sin_family = AF_INET,
                              .sin_port = htons((uint16_t)cfg->port),
                              .sin_addr = { htonl(INADDR_ANY) } };
    if (bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
        metal_die("bind :%d: %s", cfg->port, strerror(errno));
    if (listen(lfd, 4096) < 0)
        metal_die("listen: %s", strerror(errno));

    int defer_secs = 1;
    setsockopt(lfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_secs, sizeof(defer_secs));
    int tfo_qlen = 128;
    setsockopt(lfd, IPPROTO_TCP, TCP_FASTOPEN, &tfo_qlen, sizeof(tfo_qlen));

    /* io_uring with 1024 SQ entries — matches the conn pool depth.
     * The CQ defaults to 2x SQ which gives us slack for batched
     * accept+recv+send completions. */
    ring_t r;
    if (!ring_init(&r, 1024)) metal_die("ring_init failed");

    pool_t pool;
    if (!pool_init(&pool, cfg->pool_cap)) metal_die("pool_init failed");

    g_uring_state_n = pool.cap;
    g_uring_state = (uring_state_t*)calloc(g_uring_state_n, sizeof(uring_state_t));
    if (!g_uring_state) metal_die("uring_state alloc failed");

    metal_log("worker %d ready (io_uring): listen=:%d pool=%zu maxreqs=%u",
              cfg->worker_index, cfg->port, pool.cap, cfg->max_requests_per_conn);

    /* Prime: post one accept so the loop has work. */
    if (!submit_accept(&r, lfd)) metal_die("initial accept submit failed");
    unsigned pending_submit = 1;

    for (;;) {
        /* Submit anything queued, then block until at least 1 CQE. */
        int submitted = io_uring_enter(r.fd, pending_submit, 1,
                                       IORING_ENTER_GETEVENTS, NULL);
        if (submitted < 0) {
            if (errno == EINTR) continue;
            metal_log("io_uring_enter wait: %s", strerror(errno));
            continue;
        }
        pending_submit = 0;

        /* Drain all available CQEs in one pass. */
        unsigned head = atomic_load_explicit((_Atomic unsigned*)r.cq_head,
                                             memory_order_acquire);
        unsigned tail = atomic_load_explicit((_Atomic unsigned*)r.cq_tail,
                                             memory_order_acquire);
        unsigned to_submit = 0;
        while (head != tail) {
            struct io_uring_cqe* cqe = &r.cqes[head & r.cq_ring_mask];
            uint64_t ud = cqe->user_data;
            int32_t  res = cqe->res;
            uint8_t op   = ud_op(ud);
            uint64_t idx = ud_idx(ud);
            head++;   /* advance now so any `continue` below is safe */

            if (op == OP_ACCEPT) {
                /* Re-arm accept immediately so we never miss a SYN. */
                if (submit_accept(&r, lfd)) to_submit++;

                if (res < 0) {
                    if (res != -EAGAIN && res != -EINTR) {
                        metal_log("accept: %s", strerror(-res));
                    }
                } else {
                    int cfd = res;
                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    /* Add to pool. */
                    conn_t* c = pool_alloc(&pool);
                    if (!c) {
                        /* Pool exhausted — accept overflow, just drop. */
                        close(cfd);
                    } else {
                        size_t cidx = (size_t)(c - pool.base);
                        conn_init_new(c, cfd);
                        if (submit_recv(&r, c, cidx)) to_submit++;
                    }
                }
            } else if (op == OP_RECV) {
                conn_t* c = &pool.base[idx];
                g_uring_state[idx].in_flight = 0;

                if (res <= 0) {
                    /* Peer closed or error -> close the conn. */
                    if (submit_close(&r, c->fd, idx)) to_submit++;
                    c->fd = -1;
                    pool_free(&pool, c);
                    continue;
                }
                c->read_off += (size_t)res;
                c->last_active_ms = metal_now_ms_coarse();

                if (!dispatch_one(c, cfg->jt, cfg->max_requests_per_conn)) {
                    if (submit_close(&r, c->fd, idx)) to_submit++;
                    c->fd = -1;
                    pool_free(&pool, c);
                    continue;
                }

                if (c->state == ST_WRITING) {
                    if (submit_sendmsg(&r, c, idx, conn_total_payload(c))) to_submit++;
                } else {
                    /* Need more bytes. Re-arm recv. */
                    if (submit_recv(&r, c, idx)) to_submit++;
                }
            } else if (op == OP_SEND) {
                conn_t* c = &pool.base[idx];

                /* Zero-copy completion sequence is two CQEs:
                 *   1) the bytes-sent result (with IORING_CQE_F_MORE)
                 *   2) the F_NOTIF "kernel done with buffer" cqe
                 * For us, response bytes live forever in the immutable
                 * arena, so the F_NOTIF carries no useful information.
                 * Skip it entirely — do not touch in_flight / bytes_sent
                 * / state. */
                if (cqe->flags & IORING_CQE_F_NOTIF) {
                    continue;
                }

                /* Only clear in_flight when we know no more CQEs are
                 * coming for this op. With F_MORE set (zero-copy), the
                 * F_NOTIF is still pending; with it clear (regular
                 * sendmsg or final ZC result), this is the terminal
                 * CQE for the send. */
                if (!(cqe->flags & IORING_CQE_F_MORE)) {
                    g_uring_state[idx].in_flight = 0;
                }

                if (res <= 0) {
                    /* Kernel doesn't support SENDMSG_ZC (5.x kernels)?
                     * Disable zero-copy globally for this worker and
                     * resubmit the same payload as a plain SENDMSG so
                     * the response still goes out. One-time fallback;
                     * subsequent sends pick the regular opcode in
                     * submit_sendmsg automatically. */
                    if ((res == -EINVAL || res == -EOPNOTSUPP)
                        && g_uring_state[idx].last_was_zc
                        && g_uring_zc_threshold > 0) {
                        metal_log("io_uring: SENDMSG_ZC unsupported "
                                  "(res=%d), falling back to SENDMSG", res);
                        g_uring_zc_threshold = 0;
                        if (submit_sendmsg(&r, c, idx, conn_total_payload(c))) to_submit++;
                        continue;
                    }
                    if (submit_close(&r, c->fd, idx)) to_submit++;
                    c->fd = -1;
                    pool_free(&pool, c);
                    continue;
                }
                c->bytes_sent += (size_t)res;

                size_t total = conn_total_payload(c);

                if (c->bytes_sent < total) {
                    /* Partial send -> resubmit. */
                    if (submit_sendmsg(&r, c, idx, total)) to_submit++;
                    continue;
                }

                /* Response done. Record latency, then close-or-keepalive. */
                if (c->req_start_tsc && g_worker_metrics) {
                    metrics_record(g_worker_metrics, c->req_start_tsc, metal_tsc());
                    c->req_start_tsc = 0;
                }

                if (c->close_after) {
                    if (submit_close(&r, c->fd, idx)) to_submit++;
                    c->fd = -1;
                    pool_free(&pool, c);
                    continue;
                }

                conn_reset_for_next(c);
                /* If a pipelined request is already in our buffer,
                 * dispatch it immediately; else re-arm recv. */
                if (c->read_off > 0 &&
                    dispatch_one(c, cfg->jt, cfg->max_requests_per_conn) &&
                    c->state == ST_WRITING) {
                    if (submit_sendmsg(&r, c, idx, conn_total_payload(c))) to_submit++;
                } else {
                    if (submit_recv(&r, c, idx)) to_submit++;
                }
            } else if (op == OP_CLOSE) {
                /* Nothing to do — slot already returned. */
            }
        }
        atomic_store_explicit((_Atomic unsigned*)r.cq_head, head,
                              memory_order_release);

        /* Carry submissions queued during the drain into the next enter. */
        pending_submit = to_submit;
    }

    return NULL;
}
