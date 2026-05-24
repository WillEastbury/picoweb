/*
 * server_tls_kernel.c — TLS 1.3 server over kernel TCP sockets.
 *
 * This is picoweb's *baseline* TLS path: a plain AF_INET/SOCK_STREAM
 * listen socket, epoll, accept(), recv(), send(). No AF_PACKET, no
 * AF_XDP, no userspace TCP stack. The TLS engine (userspace/tls/engine)
 * is byte-driven and transport-agnostic; we just shove ciphertext
 * between recv()/send() and engine RX/TX, and shove plaintext between
 * the engine APP_IN/APP_OUT and the existing tls_bridge HTTP path.
 *
 * Architectural intent (codified in .github/copilot-instructions.md):
 *   - picoweb owns :443 end-to-end. No reverse proxy in front.
 *   - this file is the ONE TLS server path that always works on any
 *     stock Linux (incl. AKS pod networking, where AF_PACKET/AF_XDP
 *     are incompatible with kernel conntrack + LB reverse-NAT).
 *   - AF_PACKET / AF_XDP optimisations live in legacy/ and are not
 *     compiled into the default build.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "server.h"
#include "api.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <brotli/decode.h>

#include "../userspace/tls/cert.h"
#include "../userspace/tls/engine.h"
#include "../userspace/tls/pem.h"
#include "../userspace/tls/ticket_store.h"
#include "http.h"
#include "metrics.h"
#include "tls_bridge.h"
#include "util.h"

/* -----------------------------------------------------------------
 * Tunables
 * ----------------------------------------------------------------- */

#define LISTEN_BACKLOG          4096
#define EPOLL_BATCH             128
#define IDLE_SWEEP_MS           1000
#define IDLE_TIMEOUT_MS_DEFAULT 30000   /* used if cfg->idle_ms == 0   */
#define PLAIN_BUF_BYTES         8192    /* per-conn plaintext scratch  */
#define MAX_CONNS_DEFAULT       256     /* used if cfg->pool_cap == 0  */

/* TLS 1.3 session-resumption tuning. Kept identical to the AF_PACKET
 * path so existing tickets/0-RTT semantics remain unchanged. */
#define PW_TLS_TICKET_LIFETIME_S 7200u
#define PW_TLS_TICKET_MAX_EARLY  4096u
#define PW_TLS_TICKET_ID_LEN     32u
#define PW_TLS_TICKET_NONCE_LEN  16u

static const char CONN_KA[]    = "\r\n";
static const char CONN_CLOSE[] = "Connection: close\r\n\r\n";

/* -----------------------------------------------------------------
 * Per-connection + per-worker state
 * ----------------------------------------------------------------- */

typedef struct tls_kworker tls_kworker_t;

typedef enum {
    KCONN_FREE = 0,
    KCONN_LIVE,
} kconn_state_t;

typedef struct {
    kconn_state_t   state;
    int             fd;
    uint32_t        epoll_mask;
    int64_t         last_active_ms;
    uint32_t        req_count;

    tls_kworker_t*  w;
    pw_tls_engine_t eng;
    tls_bridge_t    bridge;

    size_t          plain_len;
    char            plain[PLAIN_BUF_BYTES];

    int             ticket_emitted;
    int             want_close;     /* HTTP signalled close; finish TX then exit */
    char            peer_ip[64];
} kconn_t;

struct tls_kworker {
    const server_cfg_t*    cfg;
    int                    listen_fd;
    int                    epfd;

    /* connection table sized at startup (cfg->pool_cap or
     * MAX_CONNS_DEFAULT). Heap-allocated because each kconn_t is
     * ~96+8+small KB and a stack array would overflow. */
    kconn_t*               conns;
    size_t                 conns_cap;

    /* cert material — held for the lifetime of the worker; the engine
     * BORROWS the DER buffers from us. */
    uint8_t*               cert_chain_der;
    size_t                 cert_chain_len;
    size_t                 cert_lens[8];
    unsigned               n_certs;
    cert_key_type_t        key_type;
    uint8_t                ed25519_seed[32];
    uint8_t*               key_der;
    size_t                 key_der_len;
    uint16_t               cert_sig_scheme;

    pw_tls_ticket_store_t  ticket_store;

    uint8_t*               br_identity_scratch;
    size_t                 br_identity_scratch_len;
};

/* Marker used to identify the listen-fd event vs per-conn events
 * via epoll_event.data.ptr. */
static int g_listen_marker;

static bool is_ctx_token_char(char c) {
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '_';
}

static int tls_status_for_parse_result(http_result_t pr) {
    switch (pr) {
    case HTTP_OK:      return 200;
    case HTTP_ERR_400: return 400;
    case HTTP_ERR_405: return 405;
    case HTTP_ERR_409: return 409;
    case HTTP_ERR_413: return 413;
    case HTTP_ERR_414: return 414;
    case HTTP_ERR_505: return 505;
    default:           return 500;
    }
}

static int tls_status_for_resource(const jumptable_t* jt, http_result_t pr, const resource_t* r) {
    if (!jt || !r) return tls_status_for_parse_result(pr);
    if (r == jt->err_400) return 400;
    if (r == jt->err_404) return 404;
    if (r == jt->err_405) return 405;
    if (r == jt->err_409) return 409;
    if (r == jt->err_413) return 413;
    if (r == jt->err_414) return 414;
    if (r == jt->err_500) return 500;
    if (r == jt->err_505) return 505;
    return tls_status_for_parse_result(pr);
}

static void resolve_api_request_context_tls(const http_request_t* req,
                                            api_request_context_t* ctx) {
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->tenant_system, "prod", 5);
    memcpy(ctx->tenant_id, "default", 8);
    memcpy(ctx->principal_id, "anonymous", 10);

    (void)api_principal_from_cookie(req->cookie, req->cookie_len,
                                    ctx->principal_id, sizeof(ctx->principal_id));

    if (req->host_len > 0) {
        const char* h = req->host;
        size_t n = req->host_len;
        size_t dot1 = 0;
        while (dot1 < n && h[dot1] != '.') dot1++;
        if (dot1 > 0) {
            size_t o = 0;
            for (size_t i = 0; i < dot1 && o + 1 < sizeof(ctx->tenant_id); i++) {
                char ch = h[i];
                if (!is_ctx_token_char(ch)) continue;
                ctx->tenant_id[o++] = ch;
            }
            if (o > 0) ctx->tenant_id[o] = '\0';
        }
        if (dot1 + 1 < n) {
            size_t s2 = dot1 + 1;
            size_t e2 = s2;
            while (e2 < n && h[e2] != '.') e2++;
            size_t l2 = e2 - s2;
            if ((l2 == 3 && memcmp(h + s2, "dev", 3) == 0) ||
                (l2 == 2 && memcmp(h + s2, "qa", 2) == 0) ||
                (l2 == 4 && memcmp(h + s2, "prod", 4) == 0)) {
                snprintf(ctx->tenant_system, sizeof(ctx->tenant_system), "%.*s", (int)l2, h + s2);
            }
        }
    }
}

static void api_apply_request_context_headers_tls(api_resp_t* resp,
                                                  const api_request_context_t* ctx) {
    if (!resp || !ctx) return;
    size_t rem = (resp->head_len < sizeof(resp->head)) ? (sizeof(resp->head) - resp->head_len) : 0;
    if (rem < 8) return;
    int n = snprintf(resp->head + resp->head_len, rem,
                     "X-PW-Principal-Id: %s\r\n"
                     "X-PW-Tenant-Id: %s\r\n"
                     "X-PW-Tenant-System: %s\r\n",
                     ctx->principal_id,
                     ctx->tenant_id,
                     ctx->tenant_system);
    if (n > 0 && (size_t)n < rem) resp->head_len += (size_t)n;
}

/* -----------------------------------------------------------------
 * RNG, file slurp, cert chain length parser
 *
 * These three helpers are identical in shape to the AF_PACKET path's
 * versions (server_tls.c). Duplicated here on purpose: this file is
 * meant to be readable in isolation as the production TLS path, and
 * the AF_PACKET variant is moving to legacy/ in this change.
 * ----------------------------------------------------------------- */

static int rng_fill(void* user, uint8_t* dst, size_t n) {
    (void)user;
    while (n) {
        ssize_t r = getrandom(dst, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        dst += (size_t)r;
        n   -= (size_t)r;
    }
    return 0;
}

static uint8_t* slurp_file(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || sz > (1 << 20)) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); free(buf); return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static int parse_cert_lens(const uint8_t* der, size_t der_len,
                           size_t* lens_out, unsigned* n_out) {
    size_t off = 0;
    unsigned n = 0;
    while (off < der_len && n < 8) {
        if (off + 2 > der_len || der[off] != 0x30) return -1;
        uint8_t b1 = der[off + 1];
        size_t l = 0, hdr = 0;
        if (b1 < 0x80) { l = b1; hdr = 2; }
        else {
            uint8_t nb = b1 & 0x7f;
            if (nb == 0 || nb > 4 || off + 2 + nb > der_len) return -1;
            for (uint8_t i = 0; i < nb; i++) l = (l << 8) | der[off + 2 + i];
            hdr = 2 + nb;
        }
        if (l > (1u << 20) || off + hdr + l > der_len) return -1;
        lens_out[n++] = hdr + l;
        off += hdr + l;
    }
    if (off != der_len || n == 0) return -1;
    *n_out = n;
    return 0;
}

static int load_cert_material(tls_kworker_t* w) {
    size_t cert_pem_len = 0, key_pem_len = 0;
    uint8_t* cert_pem = slurp_file(w->cfg->tls_cert_path, &cert_pem_len);
    uint8_t* key_pem  = slurp_file(w->cfg->tls_key_path,  &key_pem_len);
    if (!cert_pem || !key_pem) { free(cert_pem); free(key_pem); return -1; }

    uint8_t* chain   = (uint8_t*)malloc(cert_pem_len);
    uint8_t* key_der = (uint8_t*)malloc(key_pem_len);
    if (!chain || !key_der) {
        free(cert_pem); free(key_pem); free(chain); free(key_der); return -1;
    }

    int chain_count = 0;
    int chain_len = pem_decode_chain((const char*)cert_pem, cert_pem_len,
                                     "CERTIFICATE", chain, cert_pem_len,
                                     &chain_count);
    if (chain_len <= 0 || chain_count <= 0) goto fail;
    if (parse_cert_lens(chain, (size_t)chain_len, w->cert_lens, &w->n_certs) != 0) goto fail;

    int key_len = pem_decode((const char*)key_pem, key_pem_len, "PRIVATE KEY",
                             key_der, key_pem_len);
    int is_pkcs1_rsa = 0;
    if (key_len <= 0) {
        key_len = pem_decode((const char*)key_pem, key_pem_len,
                             "EC PRIVATE KEY", key_der, key_pem_len);
    }
    if (key_len <= 0) {
        key_len = pem_decode((const char*)key_pem, key_pem_len,
                             "RSA PRIVATE KEY", key_der, key_pem_len);
        if (key_len > 0) is_pkcs1_rsa = 1;
    }
    if (key_len <= 0) goto fail;

    cert_entry_t e = {0};
    e.key_type = is_pkcs1_rsa ? CERT_KEY_RSA
                              : cert_detect_key_type(key_der, (size_t)key_len);
    e.key_der = key_der;
    e.key_der_len = (size_t)key_len;
    w->key_type = e.key_type;
    if (w->key_type == CERT_KEY_ED25519) {
        if (cert_extract_ed25519_seed(&e, w->ed25519_seed) != 0) goto fail;
        w->cert_sig_scheme = TLS13_SIG_SCHEME_ED25519;
    } else if (w->key_type == CERT_KEY_RSA) {
        w->cert_sig_scheme = TLS13_SIG_SCHEME_RSA_PSS_RSAE_SHA256;
    } else if (w->key_type == CERT_KEY_ECDSA_P256) {
        w->cert_sig_scheme = TLS13_SIG_SCHEME_ECDSA_SECP256R1_SHA256;
    } else {
        goto fail;
    }

    w->cert_chain_der = chain;
    w->cert_chain_len = (size_t)chain_len;
    w->key_der        = key_der;
    w->key_der_len    = (size_t)key_len;

    free(cert_pem);
    free(key_pem);
    return 0;
fail:
    free(cert_pem); free(key_pem); free(chain); free(key_der);
    return -1;
}

/* -----------------------------------------------------------------
 * Listen socket + epoll plumbing
 * ----------------------------------------------------------------- */

static int make_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) metal_die("socket: %s", strerror(errno));

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
        metal_die("SO_REUSEADDR: %s", strerror(errno));
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0)
        metal_die("SO_REUSEPORT: %s", strerror(errno));
#endif

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0)
        metal_die("bind :%d: %s", port, strerror(errno));
    if (listen(fd, LISTEN_BACKLOG) != 0)
        metal_die("listen: %s", strerror(errno));

    /* No TCP_DEFER_ACCEPT: a TLS client's first wire bytes are the
     * ClientHello, so DEFER_ACCEPT helps. Enable it. */
    int defer_secs = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_secs, sizeof(defer_secs));
    return fd;
}

static void ep_add(int ep, int fd, void* ptr, uint32_t events) {
    struct epoll_event ev = { .events = events, .data.ptr = ptr };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) != 0)
        metal_log("epoll_ctl ADD fd=%d: %s", fd, strerror(errno));
}
static void ep_mod(int ep, int fd, void* ptr, uint32_t events) {
    struct epoll_event ev = { .events = events, .data.ptr = ptr };
    if (epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev) != 0)
        metal_log("epoll_ctl MOD fd=%d: %s", fd, strerror(errno));
}
static inline void ep_mod_if(int ep, kconn_t* c, uint32_t events) {
    if (c->epoll_mask == events) return;
    c->epoll_mask = events;
    ep_mod(ep, c->fd, c, events);
}

/* -----------------------------------------------------------------
 * Connection allocation
 * ----------------------------------------------------------------- */

static kconn_t* kconn_alloc(tls_kworker_t* w) {
    for (size_t i = 0; i < w->conns_cap; i++) {
        kconn_t* c = &w->conns[i];
        if (c->state == KCONN_FREE) return c;
    }
    return NULL;
}

static void kconn_init(kconn_t* c, tls_kworker_t* w, int fd, int64_t now_ms) {
    /* Engine carries ~100KB of buffers; do NOT memset() the whole thing
     * blindly — pw_tls_engine_init takes care of the engine's own state.
     * We just zero the bookkeeping fields. */
    c->state          = KCONN_LIVE;
    c->fd             = fd;
    c->epoll_mask     = 0;
    c->last_active_ms = now_ms;
    c->req_count      = 0;
    c->w              = w;
    c->plain_len      = 0;
    c->ticket_emitted = 0;
    c->want_close     = 0;
    tls_bridge_init(&c->bridge, w->cfg->jt);
    pw_tls_engine_init(&c->eng);
    if (pw_tls_engine_configure_server(&c->eng, rng_fill, NULL,
                                       w->cert_sig_scheme,
                                       w->ed25519_seed,
                                       w->key_der,
                                       w->key_der_len,
                                       w->cert_chain_der,
                                       w->cert_lens,
                                       w->n_certs) != 0) {
        /* configure_server should not fail with material we already
         * validated at startup; treat as fatal-per-conn. */
        c->state = KCONN_FREE;
        c->fd = -1;
        return;
    }
    pw_tls_engine_attach_resumption(&c->eng, &w->ticket_store);
}

static void kconn_close(tls_kworker_t* w, kconn_t* c) {
    if (c->state == KCONN_FREE) return;
    if (c->fd >= 0) {
        epoll_ctl(w->epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
    /* Wipe sensitive engine state (handshake/app secrets). The engine
     * struct is reused; pw_tls_engine_init will reset internal state
     * when this slot is next allocated. */
    memset(&c->eng, 0, sizeof(c->eng));
    c->state = KCONN_FREE;
    c->plain_len = 0;
    c->ticket_emitted = 0;
    c->want_close = 0;
}

/* -----------------------------------------------------------------
 * HTTP response builder (iov form) — copy of server_tls.c's helper,
 * unchanged. Pulled in here because the AF_PACKET file is moving to
 * legacy/ and we want this file to compile on its own.
 * ----------------------------------------------------------------- */

static int build_http_response_iov(kconn_t* c,
                                   http_result_t pr, http_request_t* req,
                                   pw_iov_t* out, unsigned* out_n,
                                   bool* out_close_after,
                                   int* out_status) {
    tls_kworker_t* w = c->w;
    bool close_after = false, head_only = false;
    const resource_t* r = http_select(w->cfg->jt, pr, req, &close_after, &head_only);
    c->req_count++;
    if (w->cfg->max_requests_per_conn &&
        c->req_count >= w->cfg->max_requests_per_conn) close_after = true;

    const resource_compress_t* variant = NULL;
    if (pr == HTTP_OK) {
        if      (req->accept_br && r->brotli)     variant = r->brotli;
        else if (req->accept_pc && r->compressed) variant = r->compressed;
    }

    if (pr == HTTP_OK && req->if_none_match &&
        (req->method == M_GET || req->method == M_HEAD)) {
        const char* etag = NULL;
        const char* w304 = NULL;
        size_t w304_len  = 0;
        if (variant) {
            etag = variant->etag; w304 = variant->wire_304; w304_len = variant->wire_304_len;
        } else if (r->etag[0] != '\0') {
            etag = r->etag; w304 = r->wire_304; w304_len = r->wire_304_len;
        }
        if (etag && w304 && etag_matches(req->if_none_match, req->if_none_match_len, etag)) {
            unsigned n304 = 0;
            out[n304++] = (pw_iov_t){ .base = (const uint8_t*)w304, .len = w304_len };
            out[n304++] = (pw_iov_t){
                .base = close_after ? (const uint8_t*)CONN_CLOSE : (const uint8_t*)CONN_KA,
                .len  = close_after ? (sizeof(CONN_CLOSE) - 1) : (sizeof(CONN_KA) - 1)
            };
            *out_n = n304;
            *out_close_after = close_after;
            if (out_status) *out_status = 304;
            return 0;
        }
    }

    const uint8_t* decoded_body = NULL;
    size_t decoded_body_len = 0;
    if (pr == HTTP_OK && !head_only && !variant &&
        r->brotli_primary && r->brotli) {
        size_t need = r->identity_len ? r->identity_len : r->brotli->decoded_len;
        if (!w->br_identity_scratch || need > w->br_identity_scratch_len) {
            metal_log("brotli identity scratch too small: need=%zu have=%zu",
                      need, w->br_identity_scratch_len);
            r = w->cfg->jt->err_500;
            close_after = true;
        } else {
            size_t out_len = need;
            BrotliDecoderResult brc = BrotliDecoderDecompress(
                r->brotli->body_len,
                (const uint8_t*)r->brotli->body,
                &out_len,
                w->br_identity_scratch);
            if (brc != BROTLI_DECODER_RESULT_SUCCESS || out_len != need) {
                metal_log("brotli identity decode failed: rc=%d out=%zu need=%zu",
                          (int)brc, out_len, need);
                r = w->cfg->jt->err_500;
                close_after = true;
            } else {
                decoded_body = w->br_identity_scratch;
                decoded_body_len = out_len;
            }
        }
    }

    unsigned n = 0;
    out[n++] = (pw_iov_t){
        .base = (const uint8_t*)(variant ? variant->head : r->head),
        .len  = variant ? variant->head_len : r->head_len
    };
    out[n++] = (pw_iov_t){
        .base = close_after ? (const uint8_t*)CONN_CLOSE : (const uint8_t*)CONN_KA,
        .len  = close_after ? (sizeof(CONN_CLOSE) - 1) : (sizeof(CONN_KA) - 1)
    };

    if (!head_only) {
        if (variant) {
            out[n++] = (pw_iov_t){ .base = (const uint8_t*)variant->body, .len = variant->body_len };
        } else if (decoded_body) {
            out[n++] = (pw_iov_t){ .base = decoded_body, .len = decoded_body_len };
        } else {
            if (r->chrome && r->chrome->hdr_len)
                out[n++] = (pw_iov_t){ .base = (const uint8_t*)r->chrome->hdr, .len = r->chrome->hdr_len };
            if (r->body_len)
                out[n++] = (pw_iov_t){ .base = (const uint8_t*)r->body, .len = r->body_len };
            if (r->chrome && r->chrome->ftr_len)
                out[n++] = (pw_iov_t){ .base = (const uint8_t*)r->chrome->ftr, .len = r->chrome->ftr_len };
        }
    }

    *out_n = n;
    *out_close_after = close_after;
    if (out_status) *out_status = tls_status_for_resource(w->cfg->jt, pr, r);
    return 0;
}

static int build_api_response_iov(kconn_t* c, const http_request_t* req,
                                  api_resp_t* api_resp,
                                  pw_iov_t* out, unsigned* out_n,
                                  bool* out_close_after) {
    memset(api_resp, 0, sizeof(*api_resp));

    const char* body = c->plain + req->consumed;
    api_request_context_t req_ctx;
    resolve_api_request_context_tls(req, &req_ctx);
    if (c->peer_ip[0]) {
        snprintf(req_ctx.client_ip, sizeof(req_ctx.client_ip), "%s", c->peer_ip);
    }
    api_dispatch(req->method, req->path, req->path_len,
                 body, req->content_length,
                 req->cookie, req->cookie_len,
                 req->pw_auth_header,
                 req->score_token, req->score_token_len,
                 &req_ctx,
                 api_resp);
    api_apply_request_context_headers_tls(api_resp, &req_ctx);
    api_apply_cors(api_resp,
                   req->origin, req->origin_len,
                   req->acr_headers, req->acr_headers_len);

    c->req_count++;

    unsigned n = 0;
    out[n++] = (pw_iov_t){ .base = (const uint8_t*)api_resp->head, .len = api_resp->head_len };
    out[n++] = (pw_iov_t){ .base = (const uint8_t*)CONN_CLOSE, .len = sizeof(CONN_CLOSE) - 1 };
    if (req->method != M_HEAD && api_resp->body && api_resp->body_len > 0) {
        out[n++] = (pw_iov_t){ .base = (const uint8_t*)api_resp->body, .len = api_resp->body_len };
    }
    *out_n = n;
    *out_close_after = true;
    return 0;
}

/* 103 Early Hints (best-effort). Same logic as the AF_PACKET path. */
static void maybe_seal_103(kconn_t* c, http_result_t pr, http_request_t* req) {
    tls_kworker_t* w = c->w;
    if (!w || !w->cfg || !w->cfg->http_early_hints) return;
    if (pr != HTTP_OK) return;
    if (req->method != M_GET) return;

    bool ca = false, ho = false;
    const resource_t* r = http_select(w->cfg->jt, pr, req, &ca, &ho);
    if (!r || ho || !r->link_hdr || r->link_hdr_len == 0) return;

    if (req->if_none_match) {
        const char* etag = NULL;
        if      (req->accept_br && r->brotli)     etag = r->brotli->etag;
        else if (req->accept_pc && r->compressed) etag = r->compressed->etag;
        else if (r->etag[0] != '\0')              etag = r->etag;
        if (etag && etag_matches(req->if_none_match,
                                 req->if_none_match_len, etag)) return;
    }

    static const char status[] = "HTTP/1.1 103 Early Hints\r\n";
    static const char term[]   = "\r\n";
    pw_iov_t iov[3] = {
        { .base = (const uint8_t*)status,        .len = sizeof(status) - 1 },
        { .base = (const uint8_t*)r->link_hdr,   .len = r->link_hdr_len    },
        { .base = (const uint8_t*)term,          .len = sizeof(term) - 1   },
    };
    (void)pw_tls_app_seal_iov(&c->eng, iov, 3);
}

/* NewSessionTicket emit. Same logic as the AF_PACKET path. */
static inline void psk_wipe(uint8_t buf[32]) {
    volatile uint8_t* v = (volatile uint8_t*)buf;
    for (size_t i = 0; i < 32; i++) v[i] = 0;
}
static void maybe_emit_session_ticket(kconn_t* c) {
    if (c->ticket_emitted) return;
    if (pw_tls_state(&c->eng) != PW_TLS_ST_APP) return;

    uint8_t ticket_id[PW_TLS_TICKET_ID_LEN];
    uint8_t nonce[PW_TLS_TICKET_NONCE_LEN];
    uint8_t age_add_buf[4];
    uint8_t psk[32];

    if (rng_fill(NULL, ticket_id,   sizeof(ticket_id))   != 0) return;
    if (rng_fill(NULL, nonce,       sizeof(nonce))       != 0) return;
    if (rng_fill(NULL, age_add_buf, sizeof(age_add_buf)) != 0) return;
    uint32_t age_add = ((uint32_t)age_add_buf[0] << 24) |
                       ((uint32_t)age_add_buf[1] << 16) |
                       ((uint32_t)age_add_buf[2] <<  8) |
                       ((uint32_t)age_add_buf[3]);

    if (pw_tls_engine_emit_session_ticket(&c->eng,
                                          PW_TLS_TICKET_LIFETIME_S,
                                          age_add,
                                          nonce,     sizeof(nonce),
                                          ticket_id, sizeof(ticket_id),
                                          PW_TLS_TICKET_MAX_EARLY,
                                          psk) != 0) {
        psk_wipe(psk);
        return;
    }
    (void)pw_tls_ticket_store_insert(&c->w->ticket_store,
                                     ticket_id, sizeof(ticket_id),
                                     psk, age_add,
                                     PW_TLS_TICKET_LIFETIME_S,
                                     (uint64_t)metal_now_ms(),
                                     PW_TLS_TICKET_MAX_EARLY);
    psk_wipe(psk);
    c->ticket_emitted = 1;
}

/* -----------------------------------------------------------------
 * The state-machine core. Identical *semantics* to server_tls.c's
 * tls_on_data inner body, but transport-agnostic — it neither reads
 * a frame nor writes a frame; the caller deposits ciphertext into the
 * engine RX via pw_tls_rx_buf/ack BEFORE calling this, and drains
 * ciphertext from pw_tls_tx_buf AFTER calling this.
 *
 * Returns 0 on success, -1 on fatal protocol error (engine FAILED;
 * caller should close). Sets *out_close_after_drain=true if the HTTP
 * response said Connection: close — caller should close after the
 * engine TX buffer is fully drained.
 * ----------------------------------------------------------------- */

static int tls_drive_engine(kconn_t* c, bool* out_close_after_drain) {
    *out_close_after_drain = false;

    const uint64_t t_enter = metal_tsc();
    pw_tls_engine_set_clock(&c->eng, (uint64_t)metal_now_ms());
    int step_rc = pw_tls_step(&c->eng);
    if (step_rc < 0) {
        metal_log("tls: step failed state=%d phase=%d err=%d",
                  c->eng.state, c->eng.hs_phase, c->eng.last_err);
        return -1;
    }
    metrics_stage_add(METRICS_STAGE_TLS_STEP, metal_tsc() - t_enter);

    size_t app_len = 0;
    const uint8_t* app = pw_tls_app_in_buf(&c->eng, &app_len);
    bool close_after = false;

    /* Phase 1 — drain new plaintext into the per-conn plain buffer.
     * 0-RTT early data may arrive while still in HANDSHAKE; we accept
     * it now and defer sealing until APP. */
    if (app_len > 0) {
        if (c->plain_len + app_len > sizeof(c->plain)) {
            if (pw_tls_state(&c->eng) != PW_TLS_ST_APP) {
                pw_tls_app_in_ack(&c->eng, app_len);
                metal_log("tls: 0-RTT oversize app_len=%zu plain_len=%zu",
                          app_len, c->plain_len);
                return -1;
            }
            http_request_t dummy = {0};
            pw_iov_t resp[PW_IOV_MAX_FRAGS];
            unsigned rn = 0;
            int status = 500;
            const uint64_t t_b0 = metal_tsc();
            if (build_http_response_iov(c, HTTP_ERR_413, &dummy,
                                        resp, &rn, &close_after, &status) != 0) {
                pw_tls_app_in_ack(&c->eng, app_len);
                return -1;
            }
            metrics_stage_add(METRICS_STAGE_TLS_BUILD, metal_tsc() - t_b0);
            const uint64_t t_s0 = metal_tsc();
            if (pw_tls_app_seal_iov(&c->eng, resp, rn) != 0) {
                pw_tls_app_in_ack(&c->eng, app_len);
                return -1;
            }
            metrics_stage_add(METRICS_STAGE_TLS_SEAL, metal_tsc() - t_s0);
            c->plain_len = 0;
        } else {
            memcpy(c->plain + c->plain_len, app, app_len);
            c->plain_len += app_len;
        }
        pw_tls_app_in_ack(&c->eng, app_len);
    }

    /* Phase 2 — parse and seal pipelined HTTP requests. */
    if (pw_tls_state(&c->eng) == PW_TLS_ST_APP && c->plain_len > 0) {
        tls_bridge_t* b = &c->bridge;
        while (c->plain_len > 0) {
            const uint64_t t_p0 = metal_tsc();
            int prc = tls_bridge_parse_request(b, (const uint8_t*)c->plain, c->plain_len);
            const uint64_t t_p1 = metal_tsc();
            metrics_stage_add(METRICS_STAGE_TLS_PARSE, t_p1 - t_p0);
            if (prc == 0) break;     /* incomplete request, wait for more */

            http_request_t req = b->req;
            http_result_t  pr  = (prc == 1) ? HTTP_OK : b->parse_status;
            size_t request_bytes = req.consumed;

            if (pr == HTTP_OK && api_path_matches(req.path, req.path_len)) {
                if (req.content_length > api_max_request_body() ||
                    req.consumed + req.content_length > sizeof(c->plain)) {
                    pr = HTTP_ERR_413;
                } else if (c->plain_len < req.consumed + req.content_length) {
                    break;
                } else {
                    request_bytes = req.consumed + req.content_length;
                }
            }

            pw_iov_t resp[PW_IOV_MAX_FRAGS];
            unsigned rn = 0;
            api_resp_t api_resp = {0};
            bool is_api = (pr == HTTP_OK && api_path_matches(req.path, req.path_len));
            int status = tls_status_for_parse_result(pr);
            if (is_api) {
                if (build_api_response_iov(c, &req, &api_resp, resp, &rn, &close_after) != 0) {
                    return -1;
                }
                status = api_resp.status;
            } else {
                if (build_http_response_iov(c, pr, &req, resp, &rn, &close_after, &status) != 0) {
                    return -1;
                }
            }
            const uint64_t t_p2 = metal_tsc();
            metrics_stage_add(METRICS_STAGE_TLS_BUILD, t_p2 - t_p1);

            if (!is_api) maybe_seal_103(c, pr, &req);

            if (pw_tls_app_seal_iov(&c->eng, resp, rn) != 0) {
                api_resp_release(&api_resp);
                /* TX buffer pressure with more pipelined requests
                 * still queued: flush what we have and close. */
                close_after = true;
                c->plain_len = 0;
                break;
            }
            api_resp_release(&api_resp);
            const uint64_t t_p3 = metal_tsc();
            metrics_stage_add(METRICS_STAGE_TLS_SEAL, t_p3 - t_p2);

            size_t response_plaintext_bytes = 0;
            for (unsigned i = 0; i < rn; i++) response_plaintext_bytes += resp[i].len;
            metrics_observe_request(metrics_route_for_path(req.path, req.path_len),
                                    req.method, status, t_p3 - t_p0,
                                    request_bytes, response_plaintext_bytes,
                                    c->peer_ip, false);
            if (g_worker_metrics) {
                metrics_record(g_worker_metrics, t_p0, t_p3);
            }

            if (pr == HTTP_OK && request_bytes > 0 && c->plain_len > request_bytes) {
                size_t left = c->plain_len - request_bytes;
                memmove(c->plain, c->plain + request_bytes, left);
                c->plain_len = left;
            } else {
                c->plain_len = 0;
            }

            if (close_after) break;
        }
    }

    /* Phase 3 — emit NewSessionTicket after the user-visible response
     * is queued so TX-budget exhaustion can't starve it. */
    if (!close_after) {
        const uint64_t t_n0 = metal_tsc();
        maybe_emit_session_ticket(c);
        metrics_stage_add(METRICS_STAGE_TLS_NST, metal_tsc() - t_n0);
    }

    *out_close_after_drain = close_after;
    return 0;
}

/* -----------------------------------------------------------------
 * Per-fd I/O turns
 * ----------------------------------------------------------------- */

/* Drain pw_tls_tx_buf via send(). Returns:
 *    1  TX is fully drained
 *    0  partial send (engine still holds bytes); caller should arm
 *       EPOLLOUT
 *   -1  socket error / peer closed; caller should close
 */
static int try_drain_tx(kconn_t* c) {
    for (;;) {
        size_t tx_len = 0;
        const uint8_t* tx = pw_tls_tx_buf(&c->eng, &tx_len);
        if (tx_len == 0) return 1;

        ssize_t n = send(c->fd, tx, tx_len, MSG_NOSIGNAL);
        if (n > 0) {
            pw_tls_tx_ack(&c->eng, (size_t)n);
            metrics_stage_add(METRICS_STAGE_TLS_TX, 0);
            if ((size_t)n < tx_len) return 0;   /* partial, kernel buffer full */
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
}

/* recv as much ciphertext as the engine RX has room for, push into
 * the engine, then run tls_drive_engine. Returns:
 *    1  ok, connection healthy
 *    0  peer closed cleanly (FIN received with no bytes); caller should
 *       finish draining TX then close
 *   -1  fatal; caller should close immediately
 */
static int try_recv_and_drive(kconn_t* c, bool* out_close_after_drain) {
    *out_close_after_drain = false;

    for (;;) {
        size_t cap = 0;
        uint8_t* rx = pw_tls_rx_buf(&c->eng, &cap);
        if (cap == 0) {
            /* Engine RX full — must step before we can recv more. */
            break;
        }
        ssize_t n = recv(c->fd, rx, cap, 0);
        if (n > 0) {
            const uint64_t t_rx0 = metal_tsc();
            if (pw_tls_rx_ack(&c->eng, (size_t)n) != 0) {
                metal_log("tls: rx_ack failed n=%zd cap=%zu", n, cap);
                return -1;
            }
            metrics_stage_add(METRICS_STAGE_TLS_RX, metal_tsc() - t_rx0);
            c->last_active_ms = metal_now_ms();
            continue;
        }
        if (n == 0) {
            /* Peer FIN. Drive engine one last time, then close
             * after TX is drained. */
            bool close_after = false;
            if (tls_drive_engine(c, &close_after) != 0) return -1;
            *out_close_after_drain = true;
            return 0;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        return -1;
    }

    bool close_after = false;
    if (tls_drive_engine(c, &close_after) != 0) return -1;
    *out_close_after_drain = close_after;
    return 1;
}

static void try_accept(tls_kworker_t* w, int64_t now_ms) {
    for (;;) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        int fd = accept4(w->listen_fd, (struct sockaddr*)&peer, &peer_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            if (errno == EMFILE || errno == ENFILE) return;
            metal_log("accept4: %s", strerror(errno));
            return;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef TCP_QUICKACK
        setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif
        kconn_t* c = kconn_alloc(w);
        if (!c) {
            close(fd);
            /* Pool exhausted. Drop on the floor; client will retry. */
            continue;
        }
        kconn_init(c, w, fd, now_ms);
        c->peer_ip[0] = '\0';
        if (peer.ss_family == AF_INET) {
            struct sockaddr_in* in = (struct sockaddr_in*)&peer;
            (void)inet_ntop(AF_INET, &in->sin_addr, c->peer_ip, sizeof(c->peer_ip));
        } else if (peer.ss_family == AF_INET6) {
            struct sockaddr_in6* in6 = (struct sockaddr_in6*)&peer;
            (void)inet_ntop(AF_INET6, &in6->sin6_addr, c->peer_ip, sizeof(c->peer_ip));
        }
        if (c->state != KCONN_LIVE) {
            /* engine configure failed in init */
            close(fd);
            continue;
        }
        uint32_t mask = EPOLLIN | EPOLLRDHUP;
        c->epoll_mask = mask;
        ep_add(w->epfd, fd, c, mask);
    }
}

/* -----------------------------------------------------------------
 * Idle sweep
 * ----------------------------------------------------------------- */

static void idle_sweep(tls_kworker_t* w, int64_t now_ms) {
    int64_t timeout = w->cfg->idle_ms > 0 ? w->cfg->idle_ms : IDLE_TIMEOUT_MS_DEFAULT;
    for (size_t i = 0; i < w->conns_cap; i++) {
        kconn_t* c = &w->conns[i];
        if (c->state != KCONN_LIVE) continue;
        if (now_ms - c->last_active_ms > timeout) {
            kconn_close(w, c);
        }
    }
}

static size_t live_conn_count(tls_kworker_t* w) {
    size_t n = 0;
    for (size_t i = 0; i < w->conns_cap; i++) {
        if (w->conns[i].state == KCONN_LIVE) n++;
    }
    return n;
}

static void close_all_live(tls_kworker_t* w) {
    for (size_t i = 0; i < w->conns_cap; i++) {
        if (w->conns[i].state == KCONN_LIVE) kconn_close(w, &w->conns[i]);
    }
}

/* -----------------------------------------------------------------
 * Worker entrypoint
 * ----------------------------------------------------------------- */

void* tls_worker_main(void* arg) {
    server_cfg_t* cfg = (server_cfg_t*)arg;
    if (!cfg || !cfg->jt)
        metal_die("tls_worker_main: missing config");
    if (!cfg->tls_cert_path || !cfg->tls_key_path)
        metal_die("tls_worker_main: TLS cert/key paths required");

    tls_kworker_t* w = (tls_kworker_t*)calloc(1, sizeof(*w));
    if (!w) metal_die("tls_worker_main: OOM allocating worker context");
    w->cfg = cfg;
    w->conns_cap = cfg->pool_cap ? cfg->pool_cap : MAX_CONNS_DEFAULT;
    /* kconn_t carries an inline 8 KiB plain-text scratch plus the full
     * TLS engine state, so the per-conn slot is well past one page.
     * calloc would only fault page 0 of each slot on construction,
     * leaving the tail of every slot to fault lazily on the first
     * burst of real traffic — that's where the post-load RSS climb
     * we measured was coming from. mmap + POPULATE + memset + mlock
     * makes the whole conn table resident and pinned at startup, so
     * RSS at idle equals RSS at peak. */
    size_t conn_bytes = w->conns_cap * sizeof(kconn_t);
    void* conn_mem = mmap(NULL, conn_bytes, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS
#ifdef MAP_POPULATE
                          | MAP_POPULATE
#endif
                          , -1, 0);
    if (conn_mem == MAP_FAILED)
        metal_die("tls_worker_main: OOM allocating conn table (cap=%zu): %s",
                  w->conns_cap, strerror(errno));
#ifdef MADV_HUGEPAGE
    (void)madvise(conn_mem, conn_bytes, MADV_HUGEPAGE);
#endif
#ifdef MADV_POPULATE_WRITE
    (void)madvise(conn_mem, conn_bytes, MADV_POPULATE_WRITE);
#endif
    memset(conn_mem, 0, conn_bytes);
    if (mlock(conn_mem, conn_bytes) != 0) {
        metal_log("tls_worker: mlock conn table (%zu B) failed: %s "
                  "(add CAP_IPC_LOCK to pin)", conn_bytes, strerror(errno));
    }
    w->conns = (kconn_t*)conn_mem;

    if (cfg->jt->brotli_identity_scratch_len > 0) {
        size_t scratch_len = cfg->jt->brotli_identity_scratch_len;
        void* scratch = mmap(NULL, scratch_len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS
#ifdef MAP_POPULATE
                             | MAP_POPULATE
#endif
                             , -1, 0);
        if (scratch == MAP_FAILED) {
            metal_die("tls_worker_main: OOM allocating brotli identity scratch (%zu B): %s",
                      scratch_len, strerror(errno));
        }
#ifdef MADV_POPULATE_WRITE
        (void)madvise(scratch, scratch_len, MADV_POPULATE_WRITE);
#endif
        memset(scratch, 0, scratch_len);
        if (mlock(scratch, scratch_len) != 0) {
            metal_log("tls_worker: mlock brotli identity scratch (%zu B) failed: %s",
                      scratch_len, strerror(errno));
        }
        w->br_identity_scratch = (uint8_t*)scratch;
        w->br_identity_scratch_len = scratch_len;
    }

    pw_tls_ticket_store_init(&w->ticket_store);

    if (load_cert_material(w) != 0)
        metal_die("tls_worker_main: failed loading TLS cert/key from %s + %s",
                  cfg->tls_cert_path, cfg->tls_key_path);

    if (g_metrics && cfg->worker_index < g_n_workers) {
        g_worker_metrics = &g_metrics[cfg->worker_index];
    }

    w->listen_fd = make_listen_socket(cfg->port);
    bool listen_closed = false;
    w->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (w->epfd < 0) metal_die("epoll_create1: %s", strerror(errno));
    ep_add(w->epfd, w->listen_fd, &g_listen_marker, EPOLLIN);

    metal_log("worker %d ready: listen=:%d backend=tls io=kernel "
              "cert=%s key=%s key_type=%s conns_cap=%zu br_identity_scratch=%zu",
              cfg->worker_index, cfg->port,
              cfg->tls_cert_path, cfg->tls_key_path,
              w->key_type == CERT_KEY_ED25519    ? "ed25519" :
              w->key_type == CERT_KEY_RSA        ? "rsa-pss" :
              w->key_type == CERT_KEY_ECDSA_P256 ? "ecdsa-p256" : "?",
              w->conns_cap, w->br_identity_scratch_len);

    int64_t last_sweep_ms = metal_now_ms();
    struct epoll_event evs[EPOLL_BATCH];

    for (;;) {
        int n = epoll_wait(w->epfd, evs, EPOLL_BATCH, IDLE_SWEEP_MS);
        if (n < 0) {
            if (errno == EINTR) continue;
            metal_log("epoll_wait: %s", strerror(errno));
            continue;
        }
        int64_t now_ms = metal_now_ms();

        if (!listen_closed && server_shutdown_lameduck_elapsed()) {
            epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->listen_fd, NULL);
            close(w->listen_fd);
            w->listen_fd = -1;
            listen_closed = true;
            metal_log("worker %d draining: listen socket closed", cfg->worker_index);
        }
        if (listen_closed && live_conn_count(w) == 0) {
            metal_log("worker %d drained: no active TLS connections", cfg->worker_index);
            break;
        }
        if (server_shutdown_force_close()) {
            close_all_live(w);
            metal_log("worker %d drain deadline reached: closed active TLS connections", cfg->worker_index);
            break;
        }

        for (int i = 0; i < n; i++) {
            void* p = evs[i].data.ptr;
            uint32_t ev = evs[i].events;

            if (p == &g_listen_marker) {
                if (server_shutdown_lameduck_elapsed()) continue;
                try_accept(w, now_ms);
                continue;
            }

            kconn_t* c = (kconn_t*)p;
            if (c->state != KCONN_LIVE) continue;

            bool close_after = false;
            int rc;

            if (ev & (EPOLLERR | EPOLLHUP)) {
                kconn_close(w, c);
                continue;
            }

            if (ev & EPOLLIN) {
                rc = try_recv_and_drive(c, &close_after);
                if (rc < 0) { kconn_close(w, c); continue; }
                if (rc == 0) c->want_close = 1;
                if (close_after) c->want_close = 1;
            }

            /* Drain any TX the engine produced (handshake bytes,
             * sealed response, NewSessionTicket). */
            int drain = try_drain_tx(c);
            if (drain < 0) { kconn_close(w, c); continue; }

            uint32_t want = EPOLLRDHUP;
            if (!c->want_close) want |= EPOLLIN;
            if (drain == 0)     want |= EPOLLOUT;

            if (c->want_close && drain == 1) {
                kconn_close(w, c);
                continue;
            }

            if (ev & EPOLLRDHUP) {
                /* Peer half-closed; finish draining then close. */
                c->want_close = 1;
                if (drain == 1) { kconn_close(w, c); continue; }
            }

            ep_mod_if(w->epfd, c, want);
        }

        if (now_ms - last_sweep_ms >= IDLE_SWEEP_MS) {
            idle_sweep(w, now_ms);
            last_sweep_ms = now_ms;
        }
    }
    if (!listen_closed && w->listen_fd >= 0) close(w->listen_fd);
    if (w->epfd >= 0) close(w->epfd);
    return NULL;
}
