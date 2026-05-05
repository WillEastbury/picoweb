/* bench.c — minimal HTTP/1.1 keep-alive load generator.
 * Opens N persistent connections to 127.0.0.1:PORT, fires a fixed
 * request on each, reads responses, repeats for T seconds, reports
 * req/sec, MB/sec, latency p50/p99.
 *
 * Single-threaded epoll. Reads everything; counts responses by
 * Content-Length header in each response (very tolerant parser, but
 * sufficient for benchmarking against picoweb). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define READ_BUF 16384

typedef struct {
    int fd;
    int state;            /* 0 = need to write, 1 = reading response */
    size_t write_off;
    /* response parsing */
    size_t resp_off;      /* bytes accumulated this response */
    int    have_headers;  /* 0 until we've seen \r\n\r\n */
    int    headers_len;
    int    content_length;
    int64_t req_start_ns;
    char   buf[READ_BUF];
} con_t;

static int64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int parse_cl(const char* h, int hlen) {
    /* find "\r\nContent-Length:" (case-insensitive) */
    for (int i = 0; i + 17 < hlen; i++) {
        if (h[i] == '\r' && h[i+1] == '\n') {
            const char* p = h + i + 2;
            int rem = hlen - i - 2;
            if (rem >= 16 && strncasecmp(p, "Content-Length:", 15) == 0) {
                p += 15; rem -= 15;
                while (rem > 0 && (*p == ' ' || *p == '\t')) { p++; rem--; }
                int v = 0;
                while (rem > 0 && *p >= '0' && *p <= '9') { v = v*10 + (*p - '0'); p++; rem--; }
                return v;
            }
        }
    }
    return -1;
}

static int g_target_us = 0; /* unused */
static const char* g_request = NULL;
static int g_request_len = 0;
static int64_t g_done = 0, g_bytes = 0;
static int64_t* g_lat = NULL;
static int64_t g_lat_cap = 0, g_lat_n = 0;

static void rec_lat(int64_t v) {
    if (g_lat_n < g_lat_cap) g_lat[g_lat_n++] = v;
}

static int cmp_i64(const void* a, const void* b) {
    int64_t x = *(const int64_t*)a, y = *(const int64_t*)b;
    return x < y ? -1 : x > y;
}

static void start_req(con_t* c) {
    c->state = 0;
    c->write_off = 0;
    c->resp_off = 0;
    c->have_headers = 0;
    c->headers_len = 0;
    c->content_length = -1;
    c->req_start_ns = now_ns();
}

static void on_writable(con_t* c) {
    while (c->write_off < (size_t)g_request_len) {
        ssize_t s = send(c->fd, g_request + c->write_off,
                         g_request_len - c->write_off, MSG_NOSIGNAL);
        if (s < 0) {
            if (errno == EAGAIN) return;
            if (errno == EINTR) continue;
            perror("send"); exit(1);
        }
        c->write_off += (size_t)s;
    }
    c->state = 1;
}

static int on_readable(con_t* c) {
    for (;;) {
        ssize_t r = recv(c->fd, c->buf + c->resp_off,
                         READ_BUF - c->resp_off, 0);
        if (r < 0) {
            if (errno == EAGAIN) return 0;
            if (errno == EINTR) continue;
            perror("recv"); return -1;
        }
        if (r == 0) { fprintf(stderr, "peer closed\n"); return -1; }
        c->resp_off += (size_t)r;

        if (!c->have_headers) {
            char* end = (char*)memmem(c->buf, c->resp_off, "\r\n\r\n", 4);
            if (end) {
                c->headers_len = (int)(end - c->buf) + 4;
                c->content_length = parse_cl(c->buf, c->headers_len);
                if (c->content_length < 0) c->content_length = 0;
                c->have_headers = 1;
            }
        }
        if (c->have_headers) {
            int total = c->headers_len + c->content_length;
            if ((int)c->resp_off >= total) {
                /* full response received */
                int64_t lat = now_ns() - c->req_start_ns;
                rec_lat(lat);
                g_done++;
                g_bytes += total;
                /* shift any leftover (shouldn't happen with our fixed reqs) */
                c->resp_off = 0;
                start_req(c);
                on_writable(c);
                return 0;
            }
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s PORT CONNS SECONDS [PATH] [HOST]\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    int conns = atoi(argv[2]);
    int secs = atoi(argv[3]);
    const char* path = argc > 4 ? argv[4] : "/";
    const char* host = argc > 5 ? argv[5] : "localhost";

    static char req[1024];
    g_request_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n",
        path, host);
    g_request = req;

    g_lat_cap = 2000000;
    g_lat = (int64_t*)malloc(sizeof(int64_t) * g_lat_cap);
    if (!g_lat) { perror("malloc"); return 1; }

    int ep = epoll_create1(EPOLL_CLOEXEC);
    con_t* C = (con_t*)calloc((size_t)conns, sizeof(con_t));
    for (int i = 0; i < conns; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons((uint16_t)port);
        int rc = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
        if (rc < 0 && errno != EINPROGRESS) { perror("connect"); return 1; }
        C[i].fd = fd;
        start_req(&C[i]);
        struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT, .data.ptr = &C[i] };
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    }

    int64_t t0 = now_ns();
    int64_t t_end = t0 + (int64_t)secs * 1000000000LL;
    struct epoll_event events[1024];
    while (now_ns() < t_end) {
        int n = epoll_wait(ep, events, 1024, 100);
        for (int i = 0; i < n; i++) {
            con_t* c = (con_t*)events[i].data.ptr;
            if (c->state == 0) on_writable(c);
            if (c->state == 1) {
                if (on_readable(c) < 0) { /* drop */ epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL); close(c->fd); c->fd = -1; }
            }
        }
    }
    int64_t elapsed_ns = now_ns() - t0;
    double secs_f = elapsed_ns / 1e9;
    double rps = g_done / secs_f;
    double mbps = (g_bytes / (1024.0*1024.0)) / secs_f;

    qsort(g_lat, g_lat_n, sizeof(int64_t), cmp_i64);
    int64_t p50 = g_lat_n ? g_lat[g_lat_n / 2] : 0;
    int64_t p99 = g_lat_n ? g_lat[(g_lat_n * 99) / 100] : 0;
    int64_t pmax = g_lat_n ? g_lat[g_lat_n - 1] : 0;

    printf("conns=%d secs=%.3f reqs=%lld  rps=%.0f  throughput=%.1f MiB/s\n"
           "  latency: p50=%.1f us  p99=%.1f us  max=%.1f us\n",
           conns, secs_f, (long long)g_done, rps, mbps,
           p50 / 1000.0, p99 / 1000.0, pmax / 1000.0);
    return 0;
}
