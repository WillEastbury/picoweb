#include "server.h"
#include "http.h"
#include "metrics.h"
#include "pool.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#  include <linux/errqueue.h>   /* sock_extended_err, SO_EE_ORIGIN_ZEROCOPY */
#endif

#ifndef SO_ZEROCOPY
#  define SO_ZEROCOPY 60        /* Linux 4.14+; in case the headers are old */
#endif
#ifndef MSG_ZEROCOPY
#  define MSG_ZEROCOPY 0x4000000
#endif

#define LISTEN_BACKLOG     4096
#define EPOLL_BATCH        128
#define IDLE_SWEEP_MS      1000
#define POST_SEND_BUDGET   8     /* max requests to drain per writable cb */

/* MSG_ZEROCOPY threshold for this process. 0 = disabled. Set once by the
 * first worker that initialises (all workers carry the same cfg). Reading
 * a static int from many threads without a lock is fine because the value
 * is written exactly once before any work happens. */
static size_t g_zc_threshold = 0;

/* ============================================================== */
/* Listen socket per worker                                       */
/* ============================================================== */

static int make_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) metal_die("socket");

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
        metal_die("SO_REUSEADDR");
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0)
        metal_die("SO_REUSEPORT");
#else
#  error "SO_REUSEPORT required"
#endif

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0)
        metal_die("bind :%d", port);
    if (listen(fd, LISTEN_BACKLOG) != 0)
        metal_die("listen");

    /* TCP_DEFER_ACCEPT: kernel holds the accepted socket until data
     * arrives (or timeout), eliminating an empty-accept wakeup. */
    int defer_secs = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_secs, sizeof(defer_secs));

    /* TCP_FASTOPEN: allow data in the SYN, saving one RTT on new
     * connections from TFO-capable clients. Queue length = 128. */
    int tfo_qlen = 128;
    setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &tfo_qlen, sizeof(tfo_qlen));

    return fd;
}

/* ============================================================== */
/* Epoll helpers                                                  */
/* ============================================================== */

static void ep_add(int ep, int fd, void* ptr, uint32_t events) {
    struct epoll_event ev = {0};
    ev.events = events;
    ev.data.ptr = ptr;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
        metal_log("epoll_ctl ADD fd=%d: %s", fd, strerror(errno));
    }
}

static void ep_mod(int ep, int fd, void* ptr, uint32_t events) {
    struct epoll_event ev = {0};
    ev.events = events;
    ev.data.ptr = ptr;
    if (epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev) != 0) {
        metal_log("epoll_ctl MOD fd=%d: %s", fd, strerror(errno));
    }
}

/* Conditional ep_mod: skip syscall if mask is already what we want. */
static inline void ep_mod_if(int ep, conn_t* c, uint32_t events) {
    if (c->epoll_mask == events) return;
    c->epoll_mask = events;
    ep_mod(ep, c->fd, c, events);
}

/* Drain MSG_ERRQUEUE on a socket. Returns:
 *   0 - the queue contained only MSG_ZEROCOPY completion notifications
 *       (which we silently discard — our arena memory is immutable, so
 *       we don't care WHEN the kernel finished with each pinned page).
 *   1 - a real error was on the queue; caller should close the conn.
 *
 * Called only when EPOLLERR fires AND zerocopy is enabled. We loop until
 * recvmsg returns -1/EAGAIN to fully drain in one pass — partial drains
 * leave EPOLLERR sticky and burn epoll budget. */
#ifdef __linux__
static int drain_zc_errqueue(int fd) {
    int real_error = 0;
    /* The cmsg payload is sock_extended_err — small. 256 B headroom is
     * plenty; iov is a 1-byte sink because we don't read packet data. */
    char cbuf[256];
    char dummy;
    for (;;) {
        struct iovec iov = { .iov_base = &dummy, .iov_len = sizeof(dummy) };
        struct msghdr m = {0};
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = cbuf;
        m.msg_controllen = sizeof(cbuf);
        ssize_t r = recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            /* Anything else here itself counts as a real error. */
            real_error = 1;
            break;
        }
        for (struct cmsghdr* cm = CMSG_FIRSTHDR(&m); cm; cm = CMSG_NXTHDR(&m, cm)) {
            if ((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR) ||
                (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR)) {
                struct sock_extended_err* e = (struct sock_extended_err*)CMSG_DATA(cm);
                if (e->ee_origin != SO_EE_ORIGIN_ZEROCOPY) {
                    real_error = 1;
                }
                /* SO_EE_ORIGIN_ZEROCOPY: notification of completion. We
                 * coalesce silently. Nothing to free, nothing to update. */
            }
        }
    }
    return real_error;
}
#endif

/* ============================================================== */
/* Connection lifecycle                                           */
/* ============================================================== */

static void close_conn(pool_t* pool, int ep, conn_t* c) {
    if (c->fd >= 0) {
        epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    pool_free(pool, c);
}

/* Marker: the listen socket has data.ptr == &g_listen_marker so we can
 * distinguish it from per-connection events. */
static int g_listen_marker;

static void try_accept(int listen_fd, int ep, pool_t* pool, int64_t batch_now_ms) {
    for (;;) {
        int c = accept4(listen_fd, NULL, NULL,
                        SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            if (errno == EMFILE || errno == ENFILE) return;
            metal_log("accept4: %s", strerror(errno));
            return;
        }
        int one = 1;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef TCP_QUICKACK
        /* Reduce ACK latency on first read; kernel may auto-disable. */
        setsockopt(c, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif
        if (g_zc_threshold > 0) {
            /* Opt this socket in to MSG_ZEROCOPY. Soft-fail: if the kernel
             * doesn't support it (older than 4.14, or missing CAP_NET_RAW
             * on certain kernels) we just won't set MSG_ZEROCOPY on
             * sendmsg — plain copy still works. We log only the first
             * failure to avoid log spam. */
            if (setsockopt(c, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)) != 0) {
                static int logged = 0;
                if (!logged) {
                    metal_log("warn: SO_ZEROCOPY setsockopt: %s "
                              "(falling back to plain sendmsg)",
                              strerror(errno));
                    logged = 1;
                }
            }
        }

        conn_t* conn = pool_alloc(pool);
        if (!conn) {
            close(c);
            continue;
        }
        conn->fd = c;
        conn->state = ST_READING;
        conn->read_off = 0;
        conn->res = NULL;
        conn->seg_count = 0;
        conn->send_body = false;
        conn->bytes_sent = 0;
        conn->wire_total = 0;
        conn->close_after = false;
        conn->req_count = 0;
        conn->peer_half_closed = false;
        conn->last_active_ms = batch_now_ms;

        uint32_t mask = EPOLLIN | EPOLLRDHUP;
        conn->epoll_mask = mask;
        ep_add(ep, c, conn, mask);
    }
}

/* ============================================================== */
/* Send                                                           */
/* ============================================================== */

/* Shared connection-tail segments. The head buffer does NOT contain
 * a Connection header or the final blank line (\r\n\r\n). These
 * static tails are appended as a separate iovec segment at send time.
 *
 * HTTP/1.1 defaults to keep-alive, so the common path sends only the
 * blank-line terminator. Connection: close is explicit when needed. */
static const char CONN_KA[]    = "\r\n";                          /* 2 bytes */
static const char CONN_CLOSE[] = "Connection: close\r\n\r\n";    /* 24 bytes */
#define CONN_KA_LEN    (sizeof(CONN_KA) - 1)
#define CONN_CLOSE_LEN (sizeof(CONN_CLOSE) - 1)

/* Push as much of the prepared response out as possible. Returns:
 *   1  - response fully sent
 *   0  - partial / EAGAIN (still ST_WRITING)
 *  -1  - socket error / closed; caller should close_conn()
 *
 * Wire layout:
 *   - if no chrome: head || conn_tail || body                 (3 segments)
 *   - if  chrome  : head || conn_tail || chrome.hdr || body || chrome.ftr (up to 5)
 *
 * All responses use iovec-based sendmsg. Body data is stored ONCE
 * in the arena — no pre-concatenated wire buffers. Partial sends
 * are handled by recomputing the iovec from segs[] + bytes_sent. */

/* Build a writev iovec from the connection's seg[] array, skipping
 * past bytes_sent. Returns the segment count. */
static inline int build_iov(conn_t* c, struct iovec* iov) {
    int n = 0;
    size_t skip = c->bytes_sent;
    for (int i = 0; i < c->seg_count; i++) {
        if (skip >= c->segs[i].len) {
            skip -= c->segs[i].len;
            continue;
        }
        iov[n].iov_base = (void*)(c->segs[i].ptr + skip);
        iov[n].iov_len = c->segs[i].len - skip;
        skip = 0;
        n++;
    }
    return n;
}

static __attribute__((hot)) int try_send(conn_t* c) {
    for (;;) {
        if (c->bytes_sent >= c->wire_total) return 1;

        struct iovec iov[METAL_MAX_SEGS];
        int n = build_iov(c, iov);
        if (n == 0) return 1;

        struct msghdr m = {0};
        m.msg_iov = iov;
        m.msg_iovlen = (size_t)n;
        int flags = MSG_NOSIGNAL;
        if (g_zc_threshold > 0 && (c->wire_total - c->bytes_sent) >= g_zc_threshold)
            flags |= MSG_ZEROCOPY;
        ssize_t s = sendmsg(c->fd, &m, flags);
        if (s < 0 && errno == ENOBUFS && (flags & MSG_ZEROCOPY)) {
            flags &= ~MSG_ZEROCOPY;
            s = sendmsg(c->fd, &m, flags);
        }
        if (s < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (s == 0) return -1;
        c->bytes_sent += (size_t)s;
    }
}

/* ============================================================== */
/* Dispatch                                                       */
/* ============================================================== */

/* Try to parse one request from the front of c->read_buf and prime
 * the response. Returns:
 *   1  - request parsed & response primed; state = ST_WRITING
 *   0  - need more data; still ST_READING
 *  -1  - unrecoverable; caller should close (only for transient cases) */
static __attribute__((hot)) int dispatch_one(conn_t* c, const jumptable_t* jt, uint32_t max_req) {
    http_request_t req;
    http_result_t pr = http_parse(c->read_buf, c->read_off, &req);
    if (pr == HTTP_NEED_MORE) {
        /* Buffer-full guard applies to current request only (we
         * compact between requests). */
        if (__builtin_expect(c->read_off >= sizeof(c->read_buf), 0)) {
            pr = HTTP_ERR_413;
        } else {
            return 0;
        }
    }

    /* Latency clock: from this point we will produce a response. */
    c->req_start_tsc = metal_tsc();

    bool close_after, head_only;
    const resource_t* r = http_select(jt, pr, &req, &close_after, &head_only);

    /* Apply hard cap: serve at most max_req requests per connection.
     * Increment first so the Nth response carries Connection: close. */
    c->req_count++;
    if (max_req && c->req_count >= max_req) close_after = true;
    /* NOTE: do NOT close-after just because peer_half_closed is set —
     * the buffer may already hold further valid requests we should
     * serve. post_send() handles the "no more bytes to come" case. */

    c->res         = r;
    /* Pick encoded variant: prefer Brotli (standard, all browsers),
     * then picoweb-compress (custom clients). Only if we built one at
     * startup and the client opted in. */
    const resource_compress_t* variant = NULL;
    if (req.accept_br && r->brotli != NULL)
        variant = r->brotli;
    else if (req.accept_pc && r->compressed != NULL)
        variant = r->compressed;

    c->active_variant = variant;

    /* Build iovec segments: head + conn_tail + body pieces.
     * Compressed variants: 3 segments (head + conn_tail + compressed_body).
     * Identity chromed:    5 segments (head + conn_tail + chrome.hdr + body + chrome.ftr).
     * Identity plain:      3 segments (head + conn_tail + body).
     * 304 / HEAD:          2 segments (head + conn_tail). */
    {
        const char* head = variant ? variant->head : r->head;
        size_t head_len  = variant ? variant->head_len : r->head_len;

        int ns = 0;
        c->segs[ns].ptr = head;
        c->segs[ns].len = head_len;
        ns++;

        /* Connection tail: HTTP/1.1 defaults to keep-alive, so the
         * common path sends only "\r\n" (header terminator). Only
         * "Connection: close\r\n\r\n" when closing. */
        c->segs[ns].ptr = close_after ? CONN_CLOSE : CONN_KA;
        c->segs[ns].len = close_after ? CONN_CLOSE_LEN : CONN_KA_LEN;
        ns++;

        if (!head_only) {
            if (variant) {
                /* Compressed: chrome baked into compressed body. */
                c->segs[ns].ptr = variant->body;
                c->segs[ns].len = variant->body_len;
                ns++;
            } else {
                /* Identity: chrome segments + raw body. */
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

    /* ETag / 304 Not Modified: if the client sent If-None-Match and it
     * matches the selected variant's ETag, override with the pre-built
     * 304 wire buffer + conn tail (two segments, no body). */
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

    c->send_body   = !head_only;
    c->bytes_sent  = 0;
    c->close_after = close_after;
    c->state       = ST_WRITING;

    /* Compact: preserve any leftover bytes (start of next request)
     * at the front of the buffer for after we finish this response. */
    if (pr == HTTP_OK && req.consumed > 0 && c->read_off > req.consumed) {
        size_t leftover = c->read_off - req.consumed;
        memmove(c->read_buf, c->read_buf + req.consumed, leftover);
        c->read_off = leftover;
    } else {
        /* On parse error we close anyway; on exact-fit consume drop all. */
        c->read_off = 0;
    }
    return 1;
}

/* After a response is fully sent, either close (if close_after) or
 * transition back to ST_READING and try to dispatch any already-buffered
 * next request — bounded by POST_SEND_BUDGET to avoid one client
 * monopolising the worker. Returns true if conn was closed. */
static __attribute__((hot)) bool post_send(conn_t* c, int ep, pool_t* pool,
                      const jumptable_t* jt, uint32_t max_req,
                      int64_t batch_now_ms) {
    int budget = POST_SEND_BUDGET;
    while (budget-- > 0) {
        /* Record latency for the request that just completed. Per-worker
         * metrics: zero atomics, zero contention. Skipped if no in-flight
         * request to record (e.g. first iter before any dispatch). */
        if (c->req_start_tsc && g_worker_metrics) {
            metrics_record(g_worker_metrics, c->req_start_tsc, metal_tsc());
            c->req_start_tsc = 0;
        }

        if (c->close_after) {
            close_conn(pool, ep, c);
            return true;
        }

        /* Reset write-side state for next request. */
        c->res         = NULL;
        c->seg_count   = 0;
        c->bytes_sent  = 0;
        c->wire_total  = 0;
        c->send_body   = false;
        c->active_variant = NULL;
        c->state       = ST_READING;
        /* Use batched timestamp instead of per-request clock_gettime. */
        c->last_active_ms = batch_now_ms;

        if (c->read_off == 0) {
            /* No buffered next request. If peer half-closed, no more
             * will arrive — close now. */
            if (c->peer_half_closed) {
                close_conn(pool, ep, c);
                return true;
            }
            ep_mod_if(ep, c, EPOLLIN | EPOLLRDHUP);
            return false;
        }

        int dr = dispatch_one(c, jt, max_req);
        if (dr == 0) {
            /* Partial request buffered. If peer half-closed, no more
             * bytes will arrive to complete it — close. */
            if (c->peer_half_closed) {
                close_conn(pool, ep, c);
                return true;
            }
            ep_mod_if(ep, c, EPOLLIN | EPOLLRDHUP);
            return false;
        }
        /* dr == 1 → ST_WRITING; try to send immediately */
        int sr = try_send(c);
        if (sr < 0) { close_conn(pool, ep, c); return true; }
        if (sr == 0) {
            ep_mod_if(ep, c, EPOLLOUT | EPOLLRDHUP);
            return false;
        }
        /* sr == 1 → fully sent; loop and check for more leftover work */
    }
    /* Budget exhausted; yield back to epoll. We're either ST_WRITING
     * waiting for OUT (won't happen since sr==1 to get here) or have
     * leftover bytes to parse next tick. Re-arm IN to get re-dispatched. */
    ep_mod_if(ep, c, EPOLLIN | EPOLLRDHUP);
    return false;
}

/* ============================================================== */
/* Event handlers                                                 */
/* ============================================================== */

static __attribute__((hot)) void handle_readable(conn_t* c, int ep, pool_t* pool,
                            const jumptable_t* jt, uint32_t max_req,
                            int64_t batch_now_ms) {
    /* Drain everything currently available — LT epoll permits the
     * minimum of one read, but draining reduces wakeups. */
    bool any_read = false;
    for (;;) {
        if (c->read_off >= sizeof(c->read_buf)) break;
        ssize_t r = read(c->fd, c->read_buf + c->read_off,
                         sizeof(c->read_buf) - c->read_off);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            close_conn(pool, ep, c);
            return;
        }
        if (r == 0) {
            /* peer EOF — if we've nothing buffered, close; if we have
             * a complete request buffered, serve it then close. */
            c->peer_half_closed = true;
            if (c->read_off == 0) {
                close_conn(pool, ep, c);
                return;
            }
            break;
        }
        c->read_off += (size_t)r;
        any_read = true;
    }

    /* DO NOT refresh last_active_ms here; that defeats the slowloris
     * guard. Idle timer only ticks at request/response boundaries. */
    (void)any_read;

    if (c->read_off == 0) return;  /* nothing to parse */

    int dr = dispatch_one(c, jt, max_req);
    if (dr == 0) return;          /* still ST_READING */

    int sr = try_send(c);
    if (sr < 0) { close_conn(pool, ep, c); return; }
    if (sr == 0) {
        ep_mod_if(ep, c, EPOLLOUT | EPOLLRDHUP);
        return;
    }
    post_send(c, ep, pool, jt, max_req, batch_now_ms);
}

static void handle_writable(conn_t* c, int ep, pool_t* pool,
                            const jumptable_t* jt, uint32_t max_req,
                            int64_t batch_now_ms) {
    int rc = try_send(c);
    if (rc < 0) { close_conn(pool, ep, c); return; }
    if (rc == 0) {
        ep_mod_if(ep, c, EPOLLOUT | EPOLLRDHUP);
        return;
    }
    post_send(c, ep, pool, jt, max_req, batch_now_ms);
}

/* ============================================================== */
/* Idle sweep                                                     */
/* ============================================================== */

static void sweep_idle(pool_t* pool, int ep, int64_t now_ms, int64_t idle_ms) {
    /* Drip-proof: last_active_ms is only advanced at request/response
     * boundaries, so any conn whose timestamp is stale is closed —
     * regardless of whether it's been dribbling bytes in or out. */
    for (size_t i = 0; i < pool->cap; i++) {
        conn_t* c = &pool->base[i];
        if (c->fd < 0) continue;
        if (now_ms - c->last_active_ms > idle_ms) {
            close_conn(pool, ep, c);
        }
    }
}

/* ============================================================== */
/* Worker main                                                    */
/* ============================================================== */

void* epoll_worker_main(void* arg) {
    server_cfg_t* cfg = (server_cfg_t*)arg;

    /* Bind this thread to its own per-worker metrics_t. The hot path
     * uses g_worker_metrics directly so we don't need to thread the
     * pointer through every call. */
    if (g_metrics && cfg->worker_index >= 0 && cfg->worker_index < g_n_workers) {
        g_worker_metrics = &g_metrics[cfg->worker_index];
    }

    /* All workers share the same MSG_ZEROCOPY threshold. Writing it from
     * worker 0 first, then identical writes from later workers, is
     * harmless — value never changes after main() spawned us. */
    if (cfg->zerocopy_threshold > 0) g_zc_threshold = cfg->zerocopy_threshold;

    pool_t pool;
    if (!pool_init(&pool, cfg->pool_cap)) {
        metal_die("pool_init(%zu)", cfg->pool_cap);
    }

    int listen_fd = make_listen_socket(cfg->port);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) metal_die("epoll_create1");
    ep_add(ep, listen_fd, &g_listen_marker, EPOLLIN);

    metal_log("worker %d ready: listen=:%d pool=%zu idle=%lldms maxreqs=%u",
              cfg->worker_index, cfg->port, cfg->pool_cap,
              (long long)cfg->idle_ms, cfg->max_requests_per_conn);

    struct epoll_event events[EPOLL_BATCH];
    int64_t last_sweep = metal_now_ms_coarse();
    uint32_t max_req = cfg->max_requests_per_conn;
    int64_t batch_now_ms = last_sweep;

    for (;;) {
        int wait_ms = (int)(IDLE_SWEEP_MS - (batch_now_ms - last_sweep));
        if (wait_ms < 0) wait_ms = 0;

        int n = epoll_wait(ep, events, EPOLL_BATCH, wait_ms);
        if (n < 0) {
            if (errno == EINTR) {
                batch_now_ms = metal_now_ms_coarse();
                continue;
            }
            metal_die("epoll_wait");
        }

        /* Batch timestamp: one clock_gettime per epoll_wait return,
         * used for idle timers and accept timestamps. */
        batch_now_ms = metal_now_ms_coarse();

        for (int i = 0; i < n; i++) {
            void* ptr = events[i].data.ptr;
            uint32_t ev = events[i].events;
            if (ptr == &g_listen_marker) {
                try_accept(listen_fd, ep, &pool, batch_now_ms);
                continue;
            }
            conn_t* c = (conn_t*)ptr;

            if (ev & EPOLLERR) {
                /* When MSG_ZEROCOPY is enabled, EPOLLERR usually fires
                 * because of completion notifications on the err queue,
                 * NOT a real socket error. Drain and discard them; only
                 * close the connection if a non-ZC error was seen. */
                if (g_zc_threshold > 0) {
                    if (drain_zc_errqueue(c->fd) == 0) {
                        /* Pure ZC notifications. Connection still good.
                         * Fall through so any other event bits (EPOLLIN,
                         * EPOLLOUT) on the same fd get handled. */
                    } else {
                        close_conn(&pool, ep, c);
                        continue;
                    }
                } else {
                    close_conn(&pool, ep, c);
                    continue;
                }
            }

            /* Track peer-half-close. Don't act on it until we either
             * naturally need to read (returns 0 → close) or finish the
             * current write (post_send sees the flag and closes). */
            if (ev & EPOLLRDHUP) c->peer_half_closed = true;

            if (c->state == ST_WRITING) {
                /* While writing we ignore EPOLLIN entirely (no
                 * pipelined-mid-response). EPOLLOUT or peer-RDHUP are
                 * the only signals that move us forward here. */
                if (ev & (EPOLLOUT | EPOLLHUP | EPOLLRDHUP)) {
                    handle_writable(c, ep, &pool, cfg->jt, max_req, batch_now_ms);
                }
                continue;
            }

            /* ST_READING */
            if (ev & EPOLLIN) {
                handle_readable(c, ep, &pool, cfg->jt, max_req, batch_now_ms);
            } else if (ev & (EPOLLHUP | EPOLLRDHUP)) {
                /* No data and peer is gone */
                close_conn(&pool, ep, c);
            }
        }

        if (batch_now_ms - last_sweep >= IDLE_SWEEP_MS) {
            sweep_idle(&pool, ep, batch_now_ms, cfg->idle_ms);
            last_sweep = batch_now_ms;
        }
    }
    return NULL;
}
