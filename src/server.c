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

static void try_accept(int listen_fd, int ep, pool_t* pool) {
    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int c = accept4(listen_fd, (struct sockaddr*)&peer, &plen,
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
        conn->head_ptr = NULL;
        conn->head_len = 0;
        conn->send_body = false;
        conn->bytes_sent = 0;
        conn->close_after = false;
        conn->req_count = 0;
        conn->peer_half_closed = false;
        conn->last_active_ms = metal_now_ms();

        ep_add(ep, c, conn, EPOLLIN | EPOLLRDHUP);
    }
}

/* ============================================================== */
/* Send                                                           */
/* ============================================================== */

/* Push as much of the prepared response out as possible. Returns:
 *   1  - response fully sent
 *   0  - partial / EAGAIN (still ST_WRITING)
 *  -1  - socket error / closed; caller should close_conn()
 *
 * Wire layout:
 *   - if no chrome: head || body                       (2 segments)
 *   - if  chrome  : head || chrome.hdr || body || chrome.ftr   (up to 4)
 *
 * The Content-Length baked into head already accounts for the chrome
 * payload, so the receiver sees one logically contiguous body of
 * (hdr+body+ftr) bytes. We walk the segment list against bytes_sent
 * to compute exactly which iovecs to emit on each call; partial sends
 * resume cleanly with no per-conn iovec storage. */
static int try_send(conn_t* c) {
    const resource_t* r = c->res;
    /* When serving a compressed variant, the wire payload is a
     * single contiguous blob — chrome bytes are baked into it. */
    bool encoded = (c->active_variant != NULL);
    const chrome_t* ch = (c->send_body && !encoded) ? r->chrome : NULL;
    const char* body_ptr = encoded ? c->active_variant->body : r->body;
    size_t      body_len = encoded ? c->active_variant->body_len : r->body_len;

    /* Build a fixed-size segment table (cheap on the stack). Using a
     * uniform walker handles both the chrome and no-chrome cases with
     * no extra branches in the hot loop. */
    const char* seg_ptr[4];
    size_t      seg_len[4];
    int seg_n = 0;
    seg_ptr[seg_n] = c->head_ptr;     seg_len[seg_n] = c->head_len;     seg_n++;
    if (c->send_body) {
        if (ch && ch->hdr_len) {
            seg_ptr[seg_n] = ch->hdr; seg_len[seg_n] = ch->hdr_len;     seg_n++;
        }
        if (body_len) {
            seg_ptr[seg_n] = body_ptr; seg_len[seg_n] = body_len;       seg_n++;
        }
        if (ch && ch->ftr_len) {
            seg_ptr[seg_n] = ch->ftr; seg_len[seg_n] = ch->ftr_len;     seg_n++;
        }
    }

    size_t total = 0;
    for (int i = 0; i < seg_n; i++) total += seg_len[i];

    for (;;) {
        if (c->bytes_sent >= total) return 1;

        /* Walk segments, skipping fully-sent ones; emit a partial
         * leading segment if bytes_sent lands mid-segment. */
        struct iovec iov[4];
        int n = 0;
        size_t cursor = 0;
        for (int i = 0; i < seg_n; i++) {
            size_t end = cursor + seg_len[i];
            if (c->bytes_sent >= end) {
                cursor = end;
                continue;
            }
            size_t off = (c->bytes_sent > cursor) ? (c->bytes_sent - cursor) : 0;
            iov[n].iov_base = (void*)(uintptr_t)(seg_ptr[i] + off);
            iov[n].iov_len  = seg_len[i] - off;
            n++;
            cursor = end;
        }

        struct msghdr m = {0};
        m.msg_iov = iov;
        m.msg_iovlen = n;
        /* MSG_ZEROCOPY pays off only above the configured byte threshold
         * (kernel docs: roughly >10 KB per send). Below that, the per-
         * send setup cost regresses throughput. We compute the remaining
         * payload (total - bytes_sent) so a partial-send tail doesn't
         * waste setup. The zerocopy_threshold value is set once at
         * startup and never changes; reading it lockless from many
         * worker threads is safe. */
        int sm_flags = MSG_NOSIGNAL;
        if (g_zc_threshold > 0 && (total - c->bytes_sent) >= g_zc_threshold) {
            sm_flags |= MSG_ZEROCOPY;
        }
        ssize_t s = sendmsg(c->fd, &m, sm_flags);
        if (s < 0 && errno == ENOBUFS && (sm_flags & MSG_ZEROCOPY)) {
            /* optmem cap hit — too many in-flight zerocopy sends. Retry
             * this exact iovec without MSG_ZEROCOPY rather than dropping
             * the connection. The next loop iteration will try again
             * once we drain the err queue (signalled via EPOLLERR). */
            sm_flags &= ~MSG_ZEROCOPY;
            s = sendmsg(c->fd, &m, sm_flags);
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
static int dispatch_one(conn_t* c, const jumptable_t* jt, uint32_t max_req) {
    http_request_t req;
    http_result_t pr = http_parse(c->read_buf, c->read_off, &req);
    if (pr == HTTP_NEED_MORE) {
        /* Buffer-full guard applies to current request only (we
         * compact between requests). */
        if (c->read_off >= sizeof(c->read_buf)) {
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
    if (variant) {
        c->head_ptr = close_after ? variant->head_close      : variant->head_keepalive;
        c->head_len = close_after ? variant->head_close_len  : variant->head_keepalive_len;
    } else {
        c->head_ptr = close_after ? r->head_close       : r->head_keepalive;
        c->head_len = close_after ? r->head_close_len   : r->head_keepalive_len;
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
static bool post_send(conn_t* c, int ep, pool_t* pool,
                      const jumptable_t* jt, uint32_t max_req) {
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
        c->head_ptr    = NULL;
        c->head_len    = 0;
        c->bytes_sent  = 0;
        c->send_body   = false;
        c->active_variant = NULL;
        c->state       = ST_READING;
        /* Refresh idle timer ONLY at request/response boundary. */
        c->last_active_ms = metal_now_ms();

        if (c->read_off == 0) {
            /* No buffered next request. If peer half-closed, no more
             * will arrive — close now. */
            if (c->peer_half_closed) {
                close_conn(pool, ep, c);
                return true;
            }
            ep_mod(ep, c->fd, c, EPOLLIN | EPOLLRDHUP);
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
            ep_mod(ep, c->fd, c, EPOLLIN | EPOLLRDHUP);
            return false;
        }
        /* dr == 1 → ST_WRITING; try to send immediately */
        int sr = try_send(c);
        if (sr < 0) { close_conn(pool, ep, c); return true; }
        if (sr == 0) {
            ep_mod(ep, c->fd, c, EPOLLOUT | EPOLLRDHUP);
            return false;
        }
        /* sr == 1 → fully sent; loop and check for more leftover work */
    }
    /* Budget exhausted; yield back to epoll. We're either ST_WRITING
     * waiting for OUT (won't happen since sr==1 to get here) or have
     * leftover bytes to parse next tick. Re-arm IN to get re-dispatched. */
    ep_mod(ep, c->fd, c, EPOLLIN | EPOLLRDHUP);
    return false;
}

/* ============================================================== */
/* Event handlers                                                 */
/* ============================================================== */

static void handle_readable(conn_t* c, int ep, pool_t* pool,
                            const jumptable_t* jt, uint32_t max_req) {
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
        ep_mod(ep, c->fd, c, EPOLLOUT | EPOLLRDHUP);
        return;
    }
    post_send(c, ep, pool, jt, max_req);
}

static void handle_writable(conn_t* c, int ep, pool_t* pool,
                            const jumptable_t* jt, uint32_t max_req) {
    int rc = try_send(c);
    if (rc < 0) { close_conn(pool, ep, c); return; }
    if (rc == 0) {
        ep_mod(ep, c->fd, c, EPOLLOUT | EPOLLRDHUP);
        return;
    }
    post_send(c, ep, pool, jt, max_req);
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
    int64_t last_sweep = metal_now_ms();
    uint32_t max_req = cfg->max_requests_per_conn;

    for (;;) {
        int64_t now = metal_now_ms();
        int wait_ms = (int)(IDLE_SWEEP_MS - (now - last_sweep));
        if (wait_ms < 0) wait_ms = 0;

        int n = epoll_wait(ep, events, EPOLL_BATCH, wait_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            metal_die("epoll_wait");
        }

        for (int i = 0; i < n; i++) {
            void* ptr = events[i].data.ptr;
            uint32_t ev = events[i].events;
            if (ptr == &g_listen_marker) {
                try_accept(listen_fd, ep, &pool);
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
                    handle_writable(c, ep, &pool, cfg->jt, max_req);
                }
                continue;
            }

            /* ST_READING */
            if (ev & EPOLLIN) {
                handle_readable(c, ep, &pool, cfg->jt, max_req);
            } else if (ev & (EPOLLHUP | EPOLLRDHUP)) {
                /* No data and peer is gone */
                close_conn(&pool, ep, c);
            }
        }

        int64_t now2 = metal_now_ms();
        if (now2 - last_sweep >= IDLE_SWEEP_MS) {
            sweep_idle(&pool, ep, now2, cfg->idle_ms);
            last_sweep = now2;
        }
    }
    return NULL;
}
