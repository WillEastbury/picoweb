#include "picowal_partition.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PP_MAX_NODES        32
#define PP_MAX_TENANTS       32
#define PP_NODES_PER_TENANT  16

#define PP_CONNECT_TIMEOUT_MS 2000
#define PP_IO_TIMEOUT_MS      4000
#define PP_RESP_CAP           (1u << 20)

typedef struct {
    char id[PICOWAL_PARTITION_NODE_ID_MAX];
} pp_node_t;

typedef struct {
    char      tenant[64];
    pp_node_t nodes[PP_NODES_PER_TENANT];
    int       n_nodes;
} pp_tenant_t;

static bool      g_enabled = false;
static bool      g_mode_proxy = false; /* false => redirect */
static char      g_self_id[PICOWAL_PARTITION_NODE_ID_MAX] = {0};
static char      g_write_token[128] = {0};

static pp_node_t g_global_nodes[PP_MAX_NODES];
static int       g_n_global_nodes = 0;

static pp_tenant_t g_tenants[PP_MAX_TENANTS];
static int         g_n_tenants = 0;

bool picowal_partition_enabled(void) { return g_enabled; }
bool picowal_partition_mode_is_proxy(void) { return g_mode_proxy; }
const char* picowal_partition_self_id(void) { return g_self_id[0] ? g_self_id : NULL; }

/* FNV-1a over a byte buffer, followed by a MurmurHash3-style 64-bit
 * finalizer (fmix64) for full avalanche -- plain FNV-1a doesn't mix a
 * short, mostly-shared-prefix input (e.g. "host:9180" vs "host:9181")
 * enough on its own: hashing only the single differing tail byte
 * amounts to one multiply-XOR step, which stays too close to linear and
 * yields near-monotonic (badly skewed) results across similar node ids.
 * Hashing the seed and node id together as one buffer, then finalizing,
 * fixes that. */
static uint64_t fnv1a_bytes(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t fmix64(uint64_t h) {
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

uint32_t picowal_partition_of_key(uint32_t key) {
    uint64_t h = fmix64(fnv1a_bytes(&key, sizeof(key)));
    return (uint32_t)(h % PICOWAL_PARTITION_COUNT);
}

static bool split_csv(const char* csv, char sep, char* out[], int max_out, int* out_n) {
    *out_n = 0;
    if (!csv || !csv[0]) return true;
    const char* p = csv;
    while (*p && *out_n < max_out) {
        const char* start = p;
        while (*p && *p != sep) p++;
        size_t len = (size_t)(p - start);
        char* tok = (char*)malloc(len + 1);
        if (!tok) return false;
        memcpy(tok, start, len);
        tok[len] = '\0';
        out[(*out_n)++] = tok;
        if (*p == sep) p++;
    }
    return !*p; /* false if we ran out of slots with input remaining */
}

static void free_toks(char* toks[], int n) {
    for (int i = 0; i < n; i++) free(toks[i]);
}

static bool add_node(pp_node_t* arr, int* n, int max, const char* id) {
    if (*n >= max) return false;
    size_t len = strlen(id);
    if (len >= sizeof(arr[0].id)) return false;
    memcpy(arr[*n].id, id, len + 1);
    (*n)++;
    return true;
}

static bool node_list_contains(const pp_node_t* arr, int n, const char* id) {
    for (int i = 0; i < n; i++) {
        if (strcmp(arr[i].id, id) == 0) return true;
    }
    return false;
}

bool picowal_partition_configure(const char* self_id, const char* nodes_csv,
                                  const char* tenant_map_csv,
                                  const char* mode,
                                  const char* write_token) {
    g_enabled = false;
    g_n_global_nodes = 0;
    g_n_tenants = 0;
    g_self_id[0] = '\0';
    g_write_token[0] = '\0';

    if (!self_id || !self_id[0] || !nodes_csv || !nodes_csv[0]) return false;
    if (strlen(self_id) >= sizeof(g_self_id)) return false;
    memcpy(g_self_id, self_id, strlen(self_id) + 1);

    if (write_token && write_token[0]) {
        if (strlen(write_token) >= sizeof(g_write_token)) return false;
        memcpy(g_write_token, write_token, strlen(write_token) + 1);
    }

    g_mode_proxy = (mode && strcmp(mode, "proxy") == 0);

    char* node_toks[PP_MAX_NODES];
    int n_node_toks = 0;
    if (!split_csv(nodes_csv, ',', node_toks, PP_MAX_NODES, &n_node_toks)) {
        free_toks(node_toks, n_node_toks);
        return false;
    }
    for (int i = 0; i < n_node_toks; i++) {
        if (!add_node(g_global_nodes, &g_n_global_nodes, PP_MAX_NODES, node_toks[i])) {
            free_toks(node_toks, n_node_toks);
            return false;
        }
    }
    free_toks(node_toks, n_node_toks);

    if (!node_list_contains(g_global_nodes, g_n_global_nodes, self_id)) {
        /* self must be a candidate owner of at least the global pool */
        return false;
    }

    if (tenant_map_csv && tenant_map_csv[0]) {
        char* entry_toks[PP_MAX_TENANTS];
        int n_entries = 0;
        if (!split_csv(tenant_map_csv, ';', entry_toks, PP_MAX_TENANTS, &n_entries)) {
            free_toks(entry_toks, n_entries);
            return false;
        }
        for (int i = 0; i < n_entries; i++) {
            char* eq = strchr(entry_toks[i], '=');
            if (!eq || eq == entry_toks[i]) { free_toks(entry_toks, n_entries); return false; }
            size_t tlen = (size_t)(eq - entry_toks[i]);
            if (tlen >= sizeof(g_tenants[0].tenant)) { free_toks(entry_toks, n_entries); return false; }
            pp_tenant_t* t = &g_tenants[g_n_tenants];
            memcpy(t->tenant, entry_toks[i], tlen);
            t->tenant[tlen] = '\0';
            t->n_nodes = 0;

            char* node_toks2[PP_NODES_PER_TENANT];
            int n_node_toks2 = 0;
            if (!split_csv(eq + 1, '|', node_toks2, PP_NODES_PER_TENANT, &n_node_toks2)) {
                free_toks(node_toks2, n_node_toks2);
                free_toks(entry_toks, n_entries);
                return false;
            }
            bool bad = false;
            for (int j = 0; j < n_node_toks2; j++) {
                if (!add_node(t->nodes, &t->n_nodes, PP_NODES_PER_TENANT, node_toks2[j])) bad = true;
            }
            free_toks(node_toks2, n_node_toks2);
            if (bad) { free_toks(entry_toks, n_entries); return false; }
            g_n_tenants++;
            if (g_n_tenants >= PP_MAX_TENANTS) break;
        }
        free_toks(entry_toks, n_entries);
    }

    g_enabled = true;
    return true;
}

static const pp_node_t* nodes_for_tenant(const char* tenant, size_t tenant_len, int* out_n) {
    if (tenant && tenant_len > 0 && tenant_len < 64) {
        char tbuf[64];
        memcpy(tbuf, tenant, tenant_len);
        tbuf[tenant_len] = '\0';
        for (int i = 0; i < g_n_tenants; i++) {
            if (strcmp(g_tenants[i].tenant, tbuf) == 0) {
                *out_n = g_tenants[i].n_nodes;
                return g_tenants[i].nodes;
            }
        }
    }
    *out_n = g_n_global_nodes;
    return g_global_nodes;
}

bool picowal_partition_owner(const char* tenant, size_t tenant_len,
                              uint32_t vpart, char* out, size_t out_cap) {
    int n = 0;
    const pp_node_t* nodes = nodes_for_tenant(tenant, tenant_len, &n);
    if (n <= 0) return false;

    /* Rendezvous (HRW) hashing: every node independently computes the
     * same winner for a given (vpart, node-set) without any coordination
     * traffic, and membership changes only reshuffle the partitions that
     * were closest between the joining/leaving node and its neighbours. */
    uint64_t best_w = 0;
    int best_i = -1;
    for (int i = 0; i < n; i++) {
        unsigned char buf[4 + PICOWAL_PARTITION_NODE_ID_MAX];
        size_t idlen = strlen(nodes[i].id);
        memcpy(buf, &vpart, sizeof(vpart));
        memcpy(buf + sizeof(vpart), nodes[i].id, idlen);
        uint64_t w = fmix64(fnv1a_bytes(buf, sizeof(vpart) + idlen));
        if (best_i < 0 || w > best_w) { best_w = w; best_i = i; }
    }
    if (best_i < 0) return false;
    size_t len = strlen(nodes[best_i].id);
    if (len >= out_cap) return false;
    memcpy(out, nodes[best_i].id, len + 1);
    return true;
}

bool picowal_partition_owner_is_self(const char* owner) {
    return owner && strcmp(owner, g_self_id) == 0;
}

void picowal_partition_redirect(const char* owner, uint32_t vpart,
                                 const char* path, size_t path_len,
                                 api_resp_t* resp) {
    resp->status = 307;
    int n = snprintf(resp->head, sizeof(resp->head),
                     "HTTP/1.1 307 Temporary Redirect\r\n"
                     "Server: picoweb\r\n"
                     "Location: http://%s%.*s\r\n"
                     "X-PW-Partition: %u\r\n"
                     "X-PW-Partition-Owner: %s\r\n"
                     "Content-Length: 0\r\n",
                     owner, (int)path_len, path, (unsigned)vpart, owner);
    if (n <= 0 || (size_t)n >= sizeof(resp->head)) {
        /* headers didn't fit (pathological path length) -- fall back */
        resp->status = 500;
        n = snprintf(resp->head, sizeof(resp->head),
                     "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n");
    }
    resp->head_len = (size_t)n;
    resp->body = NULL;
    resp->body_len = 0;
    resp->body_owned = false;
}

static void fill_502(api_resp_t* resp, const char* why) {
    resp->status = 502;
    size_t blen = strlen(why);
    int n = snprintf(resp->head, sizeof(resp->head),
                     "HTTP/1.1 502 Bad Gateway\r\nServer: picoweb\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n",
                     blen);
    resp->head_len = (n > 0) ? (size_t)n : 0;
    char* b = (char*)malloc(blen);
    if (b) { memcpy(b, why, blen); resp->body = b; resp->body_len = blen; resp->body_owned = true; }
    else { resp->body = NULL; resp->body_len = 0; resp->body_owned = false; }
}

static int pp_connect(const char* host, const char* port) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo* a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int cr = connect(fd, a->ai_addr, a->ai_addrlen);
        if (cr == 0) {
            /* connected immediately */
        } else if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, PP_CONNECT_TIMEOUT_MS);
            int soerr = 0; socklen_t solen = sizeof(soerr);
            if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen) != 0 || soerr != 0) {
                close(fd); fd = -1; continue;
            }
        } else {
            close(fd); fd = -1; continue;
        }
        if (flags >= 0) fcntl(fd, F_SETFL, flags);
        struct timeval tv;
        tv.tv_sec = PP_IO_TIMEOUT_MS / 1000;
        tv.tv_usec = (PP_IO_TIMEOUT_MS % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static const char* method_name(http_method_t m) {
    switch (m) {
    case M_GET: return "GET";
    case M_HEAD: return "HEAD";
    case M_POST: return "POST";
    case M_PUT: return "PUT";
    case M_DELETE: return "DELETE";
    case M_OPTIONS: return "OPTIONS";
    default: return "GET";
    }
}

/* Shared raw HTTP/1.1 round trip used by both picowal_partition_proxy()
 * (single-owner write forwarding) and picowal_partition_fetch()
 * (fan-out query/report gateway). Returns true and fills *out_status /
 * *out_body (caller frees, may be NULL if empty) / *out_body_len on a
 * successful round trip (any HTTP status code counts as success here --
 * false is reserved for transport-level failures). */
static bool pp_http_roundtrip(const char* node_id, const char* method_str,
                               const char* path, size_t path_len,
                               const char* body, size_t body_len,
                               const char* write_token, size_t write_token_len,
                               const char* cookie, size_t cookie_len,
                               int* out_status, char** out_body, size_t* out_body_len,
                               char* errbuf, size_t errbuf_cap) {
    *out_status = 0;
    *out_body = NULL;
    *out_body_len = 0;

    char host[PICOWAL_PARTITION_NODE_ID_MAX];
    char port[16];
    const char* colon = strrchr(node_id, ':');
    if (!colon) { snprintf(errbuf, errbuf_cap, "bad node id\n"); return false; }
    size_t hlen = (size_t)(colon - node_id);
    if (hlen >= sizeof(host)) { snprintf(errbuf, errbuf_cap, "bad node id\n"); return false; }
    memcpy(host, node_id, hlen); host[hlen] = '\0';
    snprintf(port, sizeof(port), "%s", colon + 1);

    int fd = pp_connect(host, port);
    if (fd < 0) { snprintf(errbuf, errbuf_cap, "node unreachable\n"); return false; }

    const char* tok = (write_token_len > 0) ? write_token : NULL;
    if (!tok && g_write_token[0]) tok = g_write_token;
    size_t tok_len = tok ? strlen(tok) : 0;

    char head[2048];
    int n = snprintf(head, sizeof(head),
                     "%s %.*s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: close\r\n"
                     "X-PW-Partition-Hop: 1\r\n"
                     "Content-Length: %zu\r\n",
                     method_str, (int)path_len, path, host, body_len);
    if (n <= 0 || (size_t)n >= sizeof(head)) { close(fd); snprintf(errbuf, errbuf_cap, "path too long\n"); return false; }
    size_t off = (size_t)n;
    if (tok_len > 0 && off + tok_len + 32 < sizeof(head)) {
        off += (size_t)snprintf(head + off, sizeof(head) - off, "X-PW-Write-Token: %.*s\r\n", (int)tok_len, tok);
    }
    if (cookie && cookie_len > 0 && off + cookie_len + 32 < sizeof(head)) {
        off += (size_t)snprintf(head + off, sizeof(head) - off, "Cookie: %.*s\r\n", (int)cookie_len, cookie);
    }
    if (off + 4 < sizeof(head)) {
        head[off++] = '\r'; head[off++] = '\n';
    }

    size_t sent = 0;
    while (sent < off) {
        ssize_t w = send(fd, head + sent, off - sent, 0);
        if (w < 0) { if (errno == EINTR) continue; close(fd); snprintf(errbuf, errbuf_cap, "send failed\n"); return false; }
        sent += (size_t)w;
    }
    sent = 0;
    while (body_len && sent < body_len) {
        ssize_t w = send(fd, body + sent, body_len - sent, 0);
        if (w < 0) { if (errno == EINTR) continue; close(fd); snprintf(errbuf, errbuf_cap, "send failed\n"); return false; }
        sent += (size_t)w;
    }

    char* buf = (char*)malloc(PP_RESP_CAP);
    if (!buf) { close(fd); snprintf(errbuf, errbuf_cap, "oom\n"); return false; }
    size_t got = 0;
    for (;;) {
        if (got >= PP_RESP_CAP) { free(buf); close(fd); snprintf(errbuf, errbuf_cap, "response too large\n"); return false; }
        ssize_t r = recv(fd, buf + got, PP_RESP_CAP - got, 0);
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); snprintf(errbuf, errbuf_cap, "recv failed\n"); return false; }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);

    if (got < 12 || strncmp(buf, "HTTP/1.", 7) != 0) { free(buf); snprintf(errbuf, errbuf_cap, "bad upstream response\n"); return false; }
    const char* sp = memchr(buf, ' ', got);
    if (!sp) { free(buf); snprintf(errbuf, errbuf_cap, "bad upstream response\n"); return false; }
    int status = (int)strtol(sp + 1, NULL, 10);
    if (status <= 0) { free(buf); snprintf(errbuf, errbuf_cap, "bad upstream response\n"); return false; }

    const char* hdr_end = NULL;
    for (size_t i = 0; i + 3 < got; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            hdr_end = buf + i + 4;
            break;
        }
    }
    if (!hdr_end) { free(buf); snprintf(errbuf, errbuf_cap, "bad upstream response\n"); return false; }

    size_t upstream_body_len = got - (size_t)(hdr_end - buf);
    *out_status = status;
    if (upstream_body_len > 0) {
        char* b = (char*)malloc(upstream_body_len);
        if (b) {
            memcpy(b, hdr_end, upstream_body_len);
            *out_body = b;
            *out_body_len = upstream_body_len;
        }
    }
    free(buf);
    return true;
}

bool picowal_partition_fetch(const char* node_id,
                              http_method_t method,
                              const char* path, size_t path_len,
                              const char* body, size_t body_len,
                              const char* write_token, size_t write_token_len,
                              const char* cookie, size_t cookie_len,
                              int* out_status, char** out_body, size_t* out_body_len) {
    char errbuf[128];
    return pp_http_roundtrip(node_id, method_name(method), path, path_len,
                             body, body_len, write_token, write_token_len,
                             cookie, cookie_len, out_status, out_body, out_body_len,
                             errbuf, sizeof(errbuf));
}

int picowal_partition_all_nodes(const char* tenant, size_t tenant_len,
                                 char out[][PICOWAL_PARTITION_NODE_ID_MAX], int max_out) {
    int n = 0;
    const pp_node_t* nodes = nodes_for_tenant(tenant, tenant_len, &n);
    int copied = (n < max_out) ? n : max_out;
    for (int i = 0; i < copied; i++) {
        size_t len = strlen(nodes[i].id);
        memcpy(out[i], nodes[i].id, len + 1);
    }
    return copied;
}

bool picowal_partition_proxy(const char* owner, uint32_t vpart,
                              http_method_t method,
                              const char* path, size_t path_len,
                              const char* body, size_t body_len,
                              const char* write_token, size_t write_token_len,
                              const char* cookie, size_t cookie_len,
                              api_resp_t* resp) {
    int status = 0;
    char* upstream_body = NULL;
    size_t upstream_body_len = 0;
    char errbuf[128];
    if (!pp_http_roundtrip(owner, method_name(method), path, path_len, body, body_len,
                           write_token, write_token_len, cookie, cookie_len,
                           &status, &upstream_body, &upstream_body_len,
                           errbuf, sizeof(errbuf))) {
        fill_502(resp, errbuf);
        return false;
    }

    resp->status = status;
    int hn = snprintf(resp->head, sizeof(resp->head),
                      "HTTP/1.1 %d Proxied\r\n"
                      "Server: picoweb\r\n"
                      "X-PW-Partition: %u\r\n"
                      "X-PW-Proxied-From: %s\r\n"
                      "Content-Length: %zu\r\n",
                      status, (unsigned)vpart, owner, upstream_body_len);
    resp->head_len = (hn > 0 && (size_t)hn < sizeof(resp->head)) ? (size_t)hn : 0;
    if (upstream_body_len > 0 && upstream_body) {
        resp->body = upstream_body;
        resp->body_len = upstream_body_len;
        resp->body_owned = true;
    } else {
        free(upstream_body);
    }
    return true;
}
