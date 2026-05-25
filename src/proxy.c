#include "proxy.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#define PROXY_MAX_SPECS 64
#define PROXY_BACKLOG 4096
#define PROXY_EVENTS 128
#define PROXY_BUF_CAP 65536
#define PROXY_DGRAM_CAP 65536

typedef enum {
    PROXY_PROTO_TCP = 0,
    PROXY_PROTO_UDP = 1
} proxy_proto_t;

typedef struct {
    proxy_proto_t proto;
    struct sockaddr_storage listen_addr;
    socklen_t listen_len;
    struct sockaddr_storage target_addr;
    socklen_t target_len;
    char desc[192];
} proxy_spec_t;

typedef struct {
    proxy_spec_t specs[PROXY_MAX_SPECS];
    size_t spec_count;
    int64_t udp_idle_ms;
} proxy_cfg_t;

typedef enum {
    ITEM_TCP_LISTENER = 1,
    ITEM_TCP_END,
    ITEM_UDP_LISTENER,
    ITEM_UDP_FLOW
} item_kind_t;

typedef struct {
    item_kind_t kind;
} item_base_t;

typedef struct tcp_listener {
    item_base_t base;
    int fd;
    struct sockaddr_storage target_addr;
    socklen_t target_len;
    char desc[192];
} tcp_listener_t;

typedef struct proxy_buf {
    char data[PROXY_BUF_CAP];
    size_t off;
    size_t len;
} proxy_buf_t;

struct tcp_pair;

typedef struct tcp_end {
    item_base_t base;
    struct tcp_pair* pair;
    int side;      /* 0 = client, 1 = upstream */
    int fd;
} tcp_end_t;

typedef struct tcp_pair {
    tcp_end_t end[2];
    proxy_buf_t buf[2];       /* buf[0] client->upstream, buf[1] upstream->client */
    bool eof[2];
    bool wr_shutdown[2];
    bool upstream_connected;
} tcp_pair_t;

typedef struct udp_listener udp_listener_t;

typedef struct udp_flow {
    item_base_t base;
    udp_listener_t* listener;
    struct udp_flow* next;
    int fd;
    struct sockaddr_storage client_addr;
    socklen_t client_len;
    int64_t last_active_ms;
} udp_flow_t;

struct udp_listener {
    item_base_t base;
    int fd;
    struct sockaddr_storage target_addr;
    socklen_t target_len;
    udp_flow_t* flows;
    char desc[192];
};

static void proxy_usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s --proxy=SPEC [--proxy=SPEC ...] [--udp-idle-timeout=30s]\n"
        "\n"
        "Proxy specs:\n"
        "  tcp/LISTEN_HOST:LISTEN_PORT=TARGET_HOST:TARGET_PORT\n"
        "  udp/LISTEN_HOST:LISTEN_PORT=TARGET_HOST:TARGET_PORT\n"
        "\n"
        "IPv6 addresses must be bracketed:\n"
        "  tcp/[::]:443=[::1]:444\n"
        "\n"
        "Loopback shorthand for IPv4 listeners:\n"
        "  tcp/203.0.113.10:443:444   # target is 127.0.0.1:444\n",
        argv0);
}

static int set_nonblock_cloexec(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) return -1;
    int fdfl = fcntl(fd, F_GETFD, 0);
    if (fdfl < 0) return -1;
    return fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC);
}

static bool parse_port(const char* s, uint16_t* out) {
    if (!s || !s[0]) return false;
    char* end = NULL;
    long p = strtol(s, &end, 10);
    if (end == s || *end != '\0' || p < 1 || p > 65535) return false;
    *out = (uint16_t)p;
    return true;
}

static bool copy_part(char* dst, size_t dst_len, const char* start, size_t len) {
    if (len == 0 || len >= dst_len) return false;
    memcpy(dst, start, len);
    dst[len] = '\0';
    return true;
}

static bool parse_host_port(const char* text, char* host, size_t host_len,
                            uint16_t* port) {
    if (!text || !text[0]) return false;
    if (text[0] == '[') {
        const char* close = strchr(text, ']');
        if (!close || close[1] != ':') return false;
        if (!copy_part(host, host_len, text + 1, (size_t)(close - text - 1)))
            return false;
        return parse_port(close + 2, port);
    }

    const char* colon = strrchr(text, ':');
    if (!colon) return false;
    if (strchr(text, ':') != colon) return false; /* IPv6 needs brackets. */
    if (!copy_part(host, host_len, text, (size_t)(colon - text)))
        return false;
    return parse_port(colon + 1, port);
}

static bool parse_ipv4_shorthand(const char* rest, char* listen_host,
                                 size_t listen_host_len, uint16_t* listen_port,
                                 uint16_t* target_port) {
    const char* last = strrchr(rest, ':');
    if (!last) return false;
    char tmp[256];
    if (!copy_part(tmp, sizeof(tmp), rest, (size_t)(last - rest))) return false;
    const char* mid = strrchr(tmp, ':');
    if (!mid) return false;
    if (strchr(tmp, ':') != mid) return false;
    if (!copy_part(listen_host, listen_host_len, tmp, (size_t)(mid - tmp)))
        return false;
    if (!parse_port(mid + 1, listen_port)) return false;
    return parse_port(last + 1, target_port);
}

static bool resolve_addr(const char* host, uint16_t port, int socktype,
                         bool passive, struct sockaddr_storage* out,
                         socklen_t* out_len) {
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = passive ? AI_PASSIVE : 0;

    const char* node = host;
    if (passive && (strcmp(host, "*") == 0 || strcmp(host, "0") == 0))
        node = NULL;

    struct addrinfo* res = NULL;
    int rc = getaddrinfo(node, port_text, &hints, &res);
    if (rc != 0) {
        metal_log("proxy: resolve %s:%s: %s",
                  node ? node : "*", port_text, gai_strerror(rc));
        return false;
    }
    if (!res || res->ai_addrlen > sizeof(*out)) {
        freeaddrinfo(res);
        return false;
    }
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return true;
}

static bool parse_proxy_spec(const char* spec, proxy_spec_t* out) {
    const char* slash = strchr(spec, '/');
    if (!slash || slash == spec || !slash[1]) return false;

    proxy_proto_t proto;
    if ((size_t)(slash - spec) == 3 && memcmp(spec, "tcp", 3) == 0) {
        proto = PROXY_PROTO_TCP;
    } else if ((size_t)(slash - spec) == 3 && memcmp(spec, "udp", 3) == 0) {
        proto = PROXY_PROTO_UDP;
    } else {
        return false;
    }

    char listen_host[128];
    char target_host[128];
    uint16_t listen_port = 0;
    uint16_t target_port = 0;
    const char* rest = slash + 1;
    const char* eq = strchr(rest, '=');
    if (eq) {
        char left[256];
        char right[256];
        if (!copy_part(left, sizeof(left), rest, (size_t)(eq - rest)))
            return false;
        if (strlen(eq + 1) >= sizeof(right)) return false;
        strcpy(right, eq + 1);
        if (!parse_host_port(left, listen_host, sizeof(listen_host), &listen_port))
            return false;
        if (!parse_host_port(right, target_host, sizeof(target_host), &target_port))
            return false;
    } else {
        if (!parse_ipv4_shorthand(rest, listen_host, sizeof(listen_host),
                                  &listen_port, &target_port))
            return false;
        strcpy(target_host, "127.0.0.1");
    }

    int socktype = (proto == PROXY_PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
    memset(out, 0, sizeof(*out));
    out->proto = proto;
    if (!resolve_addr(listen_host, listen_port, socktype, true,
                      &out->listen_addr, &out->listen_len))
        return false;
    if (!resolve_addr(target_host, target_port, socktype, false,
                      &out->target_addr, &out->target_len))
        return false;

    snprintf(out->desc, sizeof(out->desc), "%s/%s:%u=%s:%u",
             proto == PROXY_PROTO_TCP ? "tcp" : "udp",
             listen_host, (unsigned)listen_port, target_host,
             (unsigned)target_port);
    return true;
}

static bool parse_duration_ms(const char* s, int64_t* out) {
    if (!s || !s[0]) return false;
    char* end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || v < 1 || v > 86400000L) return false;
    if (strcmp(end, "ms") == 0 || *end == '\0') {
        *out = v;
        return true;
    }
    if (strcmp(end, "s") == 0) {
        *out = v * 1000;
        return true;
    }
    if (strcmp(end, "m") == 0) {
        *out = v * 60 * 1000;
        return true;
    }
    return false;
}

static bool parse_proxy_args(int argc, char** argv, proxy_cfg_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->udp_idle_ms = 30000;

    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];
        const char* spec = NULL;
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0 ||
            strcmp(arg, "--proxy-help") == 0) {
            proxy_usage(argv[0]);
            exit(0);
        }
        if (strcmp(arg, "--proxy") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "picoweb: --proxy requires a spec\n");
                return false;
            }
            spec = argv[i];
        } else if (strncmp(arg, "--proxy=", 8) == 0) {
            spec = arg + 8;
        } else if (strncmp(arg, "--udp-idle-timeout=", 19) == 0) {
            if (!parse_duration_ms(arg + 19, &cfg->udp_idle_ms)) {
                fprintf(stderr, "picoweb: invalid --udp-idle-timeout\n");
                return false;
            }
            continue;
        } else {
            fprintf(stderr, "picoweb: proxy mode only accepts --proxy specs and proxy flags: %s\n", arg);
            return false;
        }

        if (cfg->spec_count >= PROXY_MAX_SPECS) {
            fprintf(stderr, "picoweb: too many --proxy specs\n");
            return false;
        }
        if (!parse_proxy_spec(spec, &cfg->specs[cfg->spec_count])) {
            fprintf(stderr, "picoweb: invalid --proxy spec: %s\n", spec);
            return false;
        }
        cfg->spec_count++;
    }

    if (cfg->spec_count == 0) {
        fprintf(stderr, "picoweb: proxy mode needs at least one --proxy spec\n");
        return false;
    }
    return true;
}

static void ep_add(int ep, int fd, void* ptr, uint32_t mask) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = mask;
    ev.data.ptr = ptr;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) != 0)
        metal_die("proxy: epoll ADD fd=%d", fd);
}

static void ep_mod(int ep, int fd, void* ptr, uint32_t mask) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = mask;
    ev.data.ptr = ptr;
    if (epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev) != 0)
        metal_die("proxy: epoll MOD fd=%d", fd);
}

static void ep_del_close(int ep, int fd) {
    if (fd >= 0) {
        epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
        close(fd);
    }
}

static int make_bound_socket(const struct sockaddr_storage* addr, socklen_t addr_len,
                             int socktype, bool do_listen) {
    int fd = socket(addr->ss_family, socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (SOCK_NONBLOCK == 0 || SOCK_CLOEXEC == 0) {
        if (set_nonblock_cloexec(fd) != 0) {
            close(fd);
            return -1;
        }
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    if (socktype == SOCK_STREAM) {
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    if (bind(fd, (const struct sockaddr*)addr, addr_len) != 0) {
        close(fd);
        return -1;
    }
    if (do_listen && listen(fd, PROXY_BACKLOG) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int make_connect_socket(const struct sockaddr_storage* addr, socklen_t addr_len,
                               int socktype, int* connect_rc) {
    int fd = socket(addr->ss_family, socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (SOCK_NONBLOCK == 0 || SOCK_CLOEXEC == 0) {
        if (set_nonblock_cloexec(fd) != 0) {
            close(fd);
            return -1;
        }
    }
    if (socktype == SOCK_STREAM) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    *connect_rc = connect(fd, (const struct sockaddr*)addr, addr_len);
    if (*connect_rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

static void tcp_close_pair(int ep, tcp_pair_t* pair) {
    ep_del_close(ep, pair->end[0].fd);
    ep_del_close(ep, pair->end[1].fd);
    free(pair);
}

static void tcp_maybe_shift(proxy_buf_t* b) {
    if (b->len == 0) {
        b->off = 0;
    } else if (b->off > 0 && b->off + b->len == PROXY_BUF_CAP) {
        memmove(b->data, b->data + b->off, b->len);
        b->off = 0;
    }
}

static int tcp_try_read(tcp_pair_t* pair, int side) {
    proxy_buf_t* b = &pair->buf[side];
    tcp_maybe_shift(b);
    while (b->off + b->len < PROXY_BUF_CAP) {
        ssize_t n = recv(pair->end[side].fd, b->data + b->off + b->len,
                         PROXY_BUF_CAP - b->off - b->len, 0);
        if (n > 0) {
            b->len += (size_t)n;
            continue;
        }
        if (n == 0) {
            pair->eof[side] = true;
            return 0;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return 0;
}

static int tcp_try_write(tcp_pair_t* pair, int side) {
    if (side == 1 && !pair->upstream_connected) return 0;
    proxy_buf_t* b = &pair->buf[1 - side];
    while (b->len > 0) {
        ssize_t n = send(pair->end[side].fd, b->data + b->off, b->len, MSG_NOSIGNAL);
        if (n > 0) {
            b->off += (size_t)n;
            b->len -= (size_t)n;
            tcp_maybe_shift(b);
            continue;
        }
        if (n == 0) return -1;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return 0;
}

static bool tcp_finish_connect(tcp_pair_t* pair) {
    int err = 0;
    socklen_t err_len = sizeof(err);
    if (getsockopt(pair->end[1].fd, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0)
        return false;
    if (err != 0) {
        errno = err;
        return false;
    }
    pair->upstream_connected = true;
    return true;
}

static void tcp_apply_shutdowns(tcp_pair_t* pair) {
    if (pair->eof[0] && pair->buf[0].len == 0 && !pair->wr_shutdown[1]) {
        shutdown(pair->end[1].fd, SHUT_WR);
        pair->wr_shutdown[1] = true;
    }
    if (pair->eof[1] && pair->buf[1].len == 0 && !pair->wr_shutdown[0]) {
        shutdown(pair->end[0].fd, SHUT_WR);
        pair->wr_shutdown[0] = true;
    }
}

static bool tcp_pair_done(const tcp_pair_t* pair) {
    return pair->eof[0] && pair->eof[1] &&
           pair->buf[0].len == 0 && pair->buf[1].len == 0;
}

static void tcp_update_one(int ep, tcp_pair_t* pair, int side) {
    uint32_t mask = EPOLLRDHUP;
    if (side == 1 && !pair->upstream_connected) {
        mask |= EPOLLOUT;
    } else {
        if (!pair->eof[side] && pair->buf[side].len < PROXY_BUF_CAP)
            mask |= EPOLLIN;
        if (pair->buf[1 - side].len > 0)
            mask |= EPOLLOUT;
    }
    ep_mod(ep, pair->end[side].fd, &pair->end[side], mask);
}

static void tcp_update_pair(int ep, tcp_pair_t* pair) {
    tcp_update_one(ep, pair, 0);
    tcp_update_one(ep, pair, 1);
}

static void tcp_accept_loop(int ep, tcp_listener_t* listener) {
    for (;;) {
        int client_fd = accept4(listener->fd, NULL, NULL,
                                SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            metal_log("proxy: accept %s: %s", listener->desc, strerror(errno));
            return;
        }
        if (SOCK_NONBLOCK == 0 || SOCK_CLOEXEC == 0) {
            if (set_nonblock_cloexec(client_fd) != 0) {
                close(client_fd);
                continue;
            }
        }
        int one = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        int connect_rc = 0;
        int upstream_fd = make_connect_socket(&listener->target_addr,
                                              listener->target_len,
                                              SOCK_STREAM, &connect_rc);
        if (upstream_fd < 0) {
            close(client_fd);
            continue;
        }

        tcp_pair_t* pair = (tcp_pair_t*)calloc(1, sizeof(*pair));
        if (!pair) {
            close(client_fd);
            close(upstream_fd);
            continue;
        }
        pair->end[0].base.kind = ITEM_TCP_END;
        pair->end[0].pair = pair;
        pair->end[0].side = 0;
        pair->end[0].fd = client_fd;
        pair->end[1].base.kind = ITEM_TCP_END;
        pair->end[1].pair = pair;
        pair->end[1].side = 1;
        pair->end[1].fd = upstream_fd;
        pair->upstream_connected = (connect_rc == 0);

        ep_add(ep, client_fd, &pair->end[0], EPOLLRDHUP | EPOLLIN);
        ep_add(ep, upstream_fd, &pair->end[1],
               pair->upstream_connected ? (EPOLLRDHUP | EPOLLIN) : (EPOLLRDHUP | EPOLLOUT));
    }
}

static void tcp_handle_end(int ep, tcp_end_t* end, uint32_t mask) {
    tcp_pair_t* pair = end->pair;
    int side = end->side;

    if ((mask & EPOLLERR) && !(side == 1 && !pair->upstream_connected)) {
        tcp_close_pair(ep, pair);
        return;
    }
    if (side == 1 && !pair->upstream_connected && (mask & EPOLLOUT)) {
        if (!tcp_finish_connect(pair)) {
            tcp_close_pair(ep, pair);
            return;
        }
    }
    if (mask & EPOLLIN) {
        if (tcp_try_read(pair, side) != 0) {
            tcp_close_pair(ep, pair);
            return;
        }
    }
    if (mask & EPOLLOUT) {
        if (tcp_try_write(pair, side) != 0) {
            tcp_close_pair(ep, pair);
            return;
        }
    }
    if (mask & (EPOLLRDHUP | EPOLLHUP)) {
        pair->eof[side] = true;
    }

    if (tcp_try_write(pair, 1 - side) != 0) {
        tcp_close_pair(ep, pair);
        return;
    }
    tcp_apply_shutdowns(pair);
    if (tcp_pair_done(pair)) {
        tcp_close_pair(ep, pair);
        return;
    }
    tcp_update_pair(ep, pair);
}

static bool sockaddr_equal(const struct sockaddr_storage* a, socklen_t alen,
                           const struct sockaddr_storage* b, socklen_t blen) {
    return alen == blen && memcmp(a, b, alen) == 0;
}

static udp_flow_t* udp_find_flow(udp_listener_t* listener,
                                 const struct sockaddr_storage* client_addr,
                                 socklen_t client_len) {
    for (udp_flow_t* f = listener->flows; f; f = f->next) {
        if (sockaddr_equal(&f->client_addr, f->client_len, client_addr, client_len))
            return f;
    }
    return NULL;
}

static void udp_close_flow(int ep, udp_listener_t* listener, udp_flow_t* flow) {
    udp_flow_t** pp = &listener->flows;
    while (*pp && *pp != flow) pp = &(*pp)->next;
    if (*pp == flow) *pp = flow->next;
    ep_del_close(ep, flow->fd);
    free(flow);
}

static udp_flow_t* udp_create_flow(int ep, udp_listener_t* listener,
                                   const struct sockaddr_storage* client_addr,
                                   socklen_t client_len, int64_t now_ms) {
    int connect_rc = 0;
    int fd = make_connect_socket(&listener->target_addr, listener->target_len,
                                 SOCK_DGRAM, &connect_rc);
    if (fd < 0) return NULL;
    (void)connect_rc;

    udp_flow_t* flow = (udp_flow_t*)calloc(1, sizeof(*flow));
    if (!flow) {
        close(fd);
        return NULL;
    }
    flow->base.kind = ITEM_UDP_FLOW;
    flow->listener = listener;
    flow->fd = fd;
    memcpy(&flow->client_addr, client_addr, client_len);
    flow->client_len = client_len;
    flow->last_active_ms = now_ms;
    flow->next = listener->flows;
    listener->flows = flow;
    ep_add(ep, fd, flow, EPOLLIN);
    return flow;
}

static void udp_handle_listener(int ep, udp_listener_t* listener, int64_t now_ms) {
    char buf[PROXY_DGRAM_CAP];
    for (;;) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t n = recvfrom(listener->fd, buf, sizeof(buf), 0,
                             (struct sockaddr*)&client_addr, &client_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            metal_log("proxy: udp recv %s: %s", listener->desc, strerror(errno));
            return;
        }
        udp_flow_t* flow = udp_find_flow(listener, &client_addr, client_len);
        if (!flow) {
            flow = udp_create_flow(ep, listener, &client_addr, client_len, now_ms);
            if (!flow) continue;
        }
        flow->last_active_ms = now_ms;
        ssize_t sent = send(flow->fd, buf, (size_t)n, MSG_NOSIGNAL);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            udp_close_flow(ep, listener, flow);
        }
    }
}

static void udp_handle_flow(int ep, udp_flow_t* flow, int64_t now_ms) {
    char buf[PROXY_DGRAM_CAP];
    for (;;) {
        ssize_t n = recv(flow->fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            udp_close_flow(ep, flow->listener, flow);
            return;
        }
        flow->last_active_ms = now_ms;
        ssize_t sent = sendto(flow->listener->fd, buf, (size_t)n, MSG_NOSIGNAL,
                              (const struct sockaddr*)&flow->client_addr,
                              flow->client_len);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            udp_close_flow(ep, flow->listener, flow);
            return;
        }
    }
}

static void udp_evict_idle(int ep, udp_listener_t** listeners, size_t listener_count,
                           int64_t now_ms, int64_t idle_ms) {
    for (size_t i = 0; i < listener_count; i++) {
        udp_listener_t* listener = listeners[i];
        udp_flow_t* flow = listener->flows;
        while (flow) {
            udp_flow_t* next = flow->next;
            if (now_ms - flow->last_active_ms >= idle_ms)
                udp_close_flow(ep, listener, flow);
            flow = next;
        }
    }
}

int proxy_main(int argc, char** argv) {
    proxy_cfg_t cfg;
    if (!parse_proxy_args(argc, argv, &cfg)) {
        proxy_usage(argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) metal_die("proxy: epoll_create1");

    tcp_listener_t* tcp_listeners[PROXY_MAX_SPECS];
    udp_listener_t* udp_listeners[PROXY_MAX_SPECS];
    size_t tcp_count = 0;
    size_t udp_count = 0;

    for (size_t i = 0; i < cfg.spec_count; i++) {
        proxy_spec_t* spec = &cfg.specs[i];
        if (spec->proto == PROXY_PROTO_TCP) {
            int fd = make_bound_socket(&spec->listen_addr, spec->listen_len,
                                       SOCK_STREAM, true);
            if (fd < 0) metal_die("proxy: bind/listen %s", spec->desc);
            tcp_listener_t* listener = (tcp_listener_t*)calloc(1, sizeof(*listener));
            if (!listener) metal_die("proxy: oom tcp listener");
            listener->base.kind = ITEM_TCP_LISTENER;
            listener->fd = fd;
            memcpy(&listener->target_addr, &spec->target_addr, spec->target_len);
            listener->target_len = spec->target_len;
            snprintf(listener->desc, sizeof(listener->desc), "%s", spec->desc);
            tcp_listeners[tcp_count++] = listener;
            ep_add(ep, fd, listener, EPOLLIN);
            metal_log("picoweb proxy: %s", listener->desc);
        } else {
            int fd = make_bound_socket(&spec->listen_addr, spec->listen_len,
                                       SOCK_DGRAM, false);
            if (fd < 0) metal_die("proxy: bind udp %s", spec->desc);
            udp_listener_t* listener = (udp_listener_t*)calloc(1, sizeof(*listener));
            if (!listener) metal_die("proxy: oom udp listener");
            listener->base.kind = ITEM_UDP_LISTENER;
            listener->fd = fd;
            memcpy(&listener->target_addr, &spec->target_addr, spec->target_len);
            listener->target_len = spec->target_len;
            snprintf(listener->desc, sizeof(listener->desc), "%s", spec->desc);
            udp_listeners[udp_count++] = listener;
            ep_add(ep, fd, listener, EPOLLIN);
            metal_log("picoweb proxy: %s", listener->desc);
        }
    }
    (void)tcp_listeners;
    (void)tcp_count;

    struct epoll_event events[PROXY_EVENTS];
    int64_t last_sweep_ms = metal_now_ms_coarse();
    for (;;) {
        int n = epoll_wait(ep, events, PROXY_EVENTS, 1000);
        int64_t now_ms = metal_now_ms_coarse();
        if (n < 0) {
            if (errno == EINTR) continue;
            metal_die("proxy: epoll_wait");
        }
        for (int i = 0; i < n; i++) {
            item_base_t* item = (item_base_t*)events[i].data.ptr;
            switch (item->kind) {
            case ITEM_TCP_LISTENER:
                tcp_accept_loop(ep, (tcp_listener_t*)item);
                break;
            case ITEM_TCP_END:
                tcp_handle_end(ep, (tcp_end_t*)item, events[i].events);
                break;
            case ITEM_UDP_LISTENER:
                udp_handle_listener(ep, (udp_listener_t*)item, now_ms);
                break;
            case ITEM_UDP_FLOW:
                udp_handle_flow(ep, (udp_flow_t*)item, now_ms);
                break;
            }
        }
        if (now_ms - last_sweep_ms >= 1000) {
            udp_evict_idle(ep, udp_listeners, udp_count, now_ms, cfg.udp_idle_ms);
            last_sweep_ms = now_ms;
        }
    }
}
