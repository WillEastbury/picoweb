#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../userspace/dispatch.h"
#include "../userspace/io/af_packet.h"
#include "../userspace/tcp/ip.h"
#include "../userspace/tcp/tcp.h"
#include "../userspace/tls/cert.h"
#include "../userspace/tls/engine.h"
#include "../userspace/tls/pem.h"
#include "tls_bridge.h"
#include "util.h"

/* Shared connection-tail bytes (same semantics as epoll backend). */
static const uint8_t CONN_KA[]    = "\r\n";
static const uint8_t CONN_CLOSE[] = "Connection: close\r\n\r\n";

typedef struct tls_worker_ctx tls_worker_ctx_t;

typedef struct {
    int        in_use;
    uint32_t   req_count;
    size_t     plain_len;
    char       plain[8192];
    uint8_t    tx_stage[PW_TLS_BUF_CAP];
    size_t     tx_stage_len;
    tls_worker_ctx_t* w;
    tls_bridge_t bridge;
    pw_tls_engine_t eng;
} tls_conn_state_t;

struct tls_worker_ctx {
    const server_cfg_t* cfg;
    af_packet_t af;
    tcp_stack_t stack;
    pw_dispatch_t dispatch;
    tls_conn_state_t conns[TCP_TABLE_SIZE];

    uint8_t* cert_chain_der;
    size_t   cert_chain_len;
    size_t   cert_lens[8];
    unsigned n_certs;
    uint8_t  ed25519_seed[32];
};

static int rng_fill(void* user, uint8_t* dst, size_t n) {
    (void)user;
    while (n) {
        ssize_t r = getrandom(dst, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        dst += (size_t)r;
        n -= (size_t)r;
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
        fclose(f);
        free(buf);
        return NULL;
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
        if (b1 < 0x80) {
            l = b1;
            hdr = 2;
        } else {
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

static int load_cert_material(tls_worker_ctx_t* w) {
    size_t cert_pem_len = 0, key_pem_len = 0;
    uint8_t* cert_pem = slurp_file(w->cfg->tls_cert_path, &cert_pem_len);
    uint8_t* key_pem = slurp_file(w->cfg->tls_key_path, &key_pem_len);
    if (!cert_pem || !key_pem) {
        free(cert_pem);
        free(key_pem);
        return -1;
    }

    uint8_t* chain = (uint8_t*)malloc(cert_pem_len);
    uint8_t* key_der = (uint8_t*)malloc(key_pem_len);
    if (!chain || !key_der) {
        free(cert_pem); free(key_pem);
        free(chain); free(key_der);
        return -1;
    }

    int chain_count = 0;
    int chain_len = pem_decode_chain((const char*)cert_pem, cert_pem_len,
                                     "CERTIFICATE", chain, cert_pem_len,
                                     &chain_count);
    if (chain_len <= 0 || chain_count <= 0) goto fail;
    if (parse_cert_lens(chain, (size_t)chain_len, w->cert_lens, &w->n_certs) != 0) goto fail;

    int key_len = pem_decode((const char*)key_pem, key_pem_len, "PRIVATE KEY",
                             key_der, key_pem_len);
    if (key_len <= 0) goto fail;

    cert_entry_t e = {0};
    e.key_type = CERT_KEY_ED25519;
    e.key_der = key_der;
    e.key_der_len = (size_t)key_len;
    if (cert_extract_ed25519_seed(&e, w->ed25519_seed) != 0) goto fail;

    w->cert_chain_der = chain;
    w->cert_chain_len = (size_t)chain_len;

    free(cert_pem);
    free(key_pem);
    free(key_der);
    return 0;
fail:
    free(cert_pem);
    free(key_pem);
    free(chain);
    free(key_der);
    return -1;
}

static int parse_mac(const char* s, uint8_t out[6]) {
    if (!s) return -1;
    unsigned v[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

static int if_ipv4_addr(const char* ifname, uint32_t* out_ip_be) {
    struct ifaddrs* ifa = NULL;
    if (getifaddrs(&ifa) != 0) return -1;
    int ok = -1;
    for (struct ifaddrs* p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(p->ifa_name, ifname) != 0) continue;
        struct sockaddr_in* sin = (struct sockaddr_in*)p->ifa_addr;
        *out_ip_be = sin->sin_addr.s_addr;
        ok = 0;
        break;
    }
    freeifaddrs(ifa);
    return ok;
}

static int if_hwaddr(const char* ifname, uint8_t mac_out[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

typedef struct {
    af_packet_t* af;
} emit_ctx_t;

static void emit_seg(const tcp_seg_t* seg, void* user) {
    emit_ctx_t* e = (emit_ctx_t*)user;
    uint8_t ipbuf[1600];
    size_t n = ip_tcp_build(ipbuf, sizeof(ipbuf), seg);
    if (n == 0) return;
    (void)af_packet_send_ipv4(e->af, ipbuf, n);
}

typedef struct {
    tls_worker_ctx_t* w;
} svc_state_t;

static int build_http_response_iov(tls_conn_state_t* c,
                                   http_result_t pr, http_request_t* req,
                                   pw_iov_t* out, unsigned* out_n,
                                   bool* out_close_after) {
    tls_worker_ctx_t* w = c->w;
    if (!w) return -1;
    bool close_after = false, head_only = false;
    const resource_t* r = http_select(w->cfg->jt, pr, req, &close_after, &head_only);
    c->req_count++;
    if (w->cfg->max_requests_per_conn &&
        c->req_count >= w->cfg->max_requests_per_conn) close_after = true;

    const resource_compress_t* variant = NULL;
    if (pr == HTTP_OK && !head_only) {
        if (req->accept_br && r->brotli) variant = r->brotli;
        else if (req->accept_pc && r->compressed) variant = r->compressed;
    }

    unsigned n = 0;
    out[n++] = (pw_iov_t){
        .base = (const uint8_t*)(variant ? variant->head : r->head),
        .len  = variant ? variant->head_len : r->head_len
    };
    out[n++] = (pw_iov_t){
        .base = close_after ? CONN_CLOSE : CONN_KA,
        .len  = close_after ? (sizeof(CONN_CLOSE) - 1) : (sizeof(CONN_KA) - 1)
    };

    if (!head_only) {
        if (variant) {
            out[n++] = (pw_iov_t){ .base = (const uint8_t*)variant->body, .len = variant->body_len };
        } else {
            if (r->chrome && r->chrome->hdr_len) out[n++] = (pw_iov_t){ .base = (const uint8_t*)r->chrome->hdr, .len = r->chrome->hdr_len };
            if (r->body_len) out[n++] = (pw_iov_t){ .base = (const uint8_t*)r->body, .len = r->body_len };
            if (r->chrome && r->chrome->ftr_len) out[n++] = (pw_iov_t){ .base = (const uint8_t*)r->chrome->ftr, .len = r->chrome->ftr_len };
        }
    }

    if (pr == HTTP_OK && req->if_none_match &&
        (req->method == M_GET || req->method == M_HEAD)) {
        const char* etag = NULL;
        const char* w304 = NULL;
        size_t w304_len = 0;
        if (variant) {
            etag = variant->etag;
            w304 = variant->wire_304;
            w304_len = variant->wire_304_len;
        } else if (r->etag[0] != '\0') {
            etag = r->etag;
            w304 = r->wire_304;
            w304_len = r->wire_304_len;
        }
        if (etag && w304 && etag_matches(req->if_none_match, req->if_none_match_len, etag)) {
            n = 0;
            out[n++] = (pw_iov_t){ .base = (const uint8_t*)w304, .len = w304_len };
            out[n++] = (pw_iov_t){
                .base = close_after ? CONN_CLOSE : CONN_KA,
                .len  = close_after ? (sizeof(CONN_CLOSE) - 1) : (sizeof(CONN_KA) - 1)
            };
        }
    }

    *out_n = n;
    *out_close_after = close_after;
    return 0;
}

static void* tls_on_open(void* svc_state, const pw_conn_info_t* info) {
    (void)info;
    svc_state_t* s = (svc_state_t*)svc_state;
    tls_worker_ctx_t* w = s->w;
    for (unsigned i = 0; i < TCP_TABLE_SIZE; i++) {
        tls_conn_state_t* c = &w->conns[i];
        if (c->in_use) continue;
        memset(c, 0, sizeof(*c));
        c->in_use = 1;
        c->w = w;
        tls_bridge_init(&c->bridge, w->cfg->jt);
        pw_tls_engine_init(&c->eng);
        if (pw_tls_engine_configure_server(&c->eng, rng_fill, NULL,
                                           w->ed25519_seed,
                                           w->cert_chain_der,
                                           w->cert_lens,
                                           w->n_certs) != 0) {
            c->in_use = 0;
            return NULL;
        }
        return c;
    }
    return NULL;
}

static void tls_on_close(void* per_conn_state) {
    tls_conn_state_t* c = (tls_conn_state_t*)per_conn_state;
    if (!c) return;
    memset(c, 0, sizeof(*c));
}

static pw_disp_status_t tls_on_data(void* per_conn_state,
                                    const uint8_t* data, size_t len,
                                    pw_iov_t* iov_out, unsigned iov_max,
                                    unsigned* iov_n) {
    tls_conn_state_t* c = (tls_conn_state_t*)per_conn_state;
    if (!c || !iov_out || !iov_n || iov_max == 0) return PW_DISP_ERROR;
    *iov_n = 0;
    c->tx_stage_len = 0;

    size_t cap = 0;
    uint8_t* rx = pw_tls_rx_buf(&c->eng, &cap);
    if (len > cap) return PW_DISP_RESET;
    if (len) memcpy(rx, data, len);
    if (pw_tls_rx_ack(&c->eng, len) != 0) return PW_DISP_RESET;

    pw_tls_engine_set_clock(&c->eng, (uint64_t)metal_now_ms());
    if (pw_tls_step(&c->eng) < 0) return PW_DISP_RESET;

    size_t app_len = 0;
    const uint8_t* app = pw_tls_app_in_buf(&c->eng, &app_len);
    bool close_after = false;

    if (app_len > 0) {
        if (c->plain_len + app_len > sizeof(c->plain)) {
            http_request_t dummy = {0};
            pw_iov_t resp[PW_IOV_MAX_FRAGS];
            unsigned rn = 0;
                if (build_http_response_iov(c, HTTP_ERR_413, &dummy, resp, &rn, &close_after) != 0) {
                pw_tls_app_in_ack(&c->eng, app_len);
                return PW_DISP_RESET;
            }
            if (pw_tls_app_seal_iov(&c->eng, resp, rn) != 0) {
                pw_tls_app_in_ack(&c->eng, app_len);
                return PW_DISP_RESET;
            }
            c->plain_len = 0;
        } else {
            memcpy(c->plain + c->plain_len, app, app_len);
            c->plain_len += app_len;
            tls_bridge_t* b = &c->bridge;
            int prc = tls_bridge_parse_request(b, (const uint8_t*)c->plain, c->plain_len);
            if (prc == 1 || prc == -1) {
                http_request_t req = b->req;
                http_result_t pr = (prc == 1) ? HTTP_OK : b->parse_status;
                pw_iov_t resp[PW_IOV_MAX_FRAGS];
                unsigned rn = 0;
                if (build_http_response_iov(c, pr, &req, resp, &rn, &close_after) != 0 ||
                    pw_tls_app_seal_iov(&c->eng, resp, rn) != 0) {
                    pw_tls_app_in_ack(&c->eng, app_len);
                    return PW_DISP_RESET;
                }
                if (pr == HTTP_OK && req.consumed > 0 && c->plain_len > req.consumed) {
                    size_t left = c->plain_len - req.consumed;
                    memmove(c->plain, c->plain + req.consumed, left);
                    c->plain_len = left;
                } else {
                    c->plain_len = 0;
                }
            }
        }
        pw_tls_app_in_ack(&c->eng, app_len);
    }

    size_t tx_len = 0;
    const uint8_t* tx = pw_tls_tx_buf(&c->eng, &tx_len);
    if (tx_len > 0) {
        if (tx_len > sizeof(c->tx_stage)) return PW_DISP_RESET;
        memcpy(c->tx_stage, tx, tx_len);
        c->tx_stage_len = tx_len;
        pw_tls_tx_ack(&c->eng, tx_len);
        iov_out[0].base = c->tx_stage;
        iov_out[0].len = c->tx_stage_len;
        *iov_n = 1;
        return close_after ? PW_DISP_OUTPUT_AND_CLOSE : PW_DISP_OUTPUT;
    }
    return PW_DISP_NO_OUTPUT;
}

void* tls_worker_main(void* arg) {
    server_cfg_t* cfg = (server_cfg_t*)arg;
    if (!cfg || !cfg->jt) metal_die("tls_worker_main: missing config");
    if (!cfg->tls_ifname || !cfg->tls_ifname[0]) metal_die("tls_worker_main: --tls-ifname is required");
    if (!cfg->tls_cert_path || !cfg->tls_key_path) metal_die("tls_worker_main: resolved TLS cert/key paths are required");

    tls_worker_ctx_t w;
    memset(&w, 0, sizeof(w));
    w.cfg = cfg;
    for (unsigned i = 0; i < TCP_TABLE_SIZE; i++) w.conns[i].in_use = 0;

    if (load_cert_material(&w) != 0) {
        metal_die("tls_worker_main: failed loading TLS cert/key (need Ed25519 PKCS#8 key)");
    }

    uint8_t local_mac[6];
    uint8_t peer_mac[6] = {0};
    uint32_t local_ip = 0;
    if (if_hwaddr(cfg->tls_ifname, local_mac) != 0) {
        metal_die("tls_worker_main: failed to read MAC for ifname=%s", cfg->tls_ifname);
    }
    if (if_ipv4_addr(cfg->tls_ifname, &local_ip) != 0) {
        metal_die("tls_worker_main: failed to read IPv4 for ifname=%s", cfg->tls_ifname);
    }
    if (cfg->tls_peer_mac && parse_mac(cfg->tls_peer_mac, peer_mac) != 0) {
        metal_die("tls_worker_main: invalid --tls-peer-mac format (expected xx:xx:xx:xx:xx:xx)");
    }
    if (af_packet_open(&w.af, cfg->tls_ifname, local_mac, peer_mac) != 0) {
        metal_die("tls_worker_main: af_packet_open(ifname=%s)", cfg->tls_ifname);
    }

    pw_dispatch_init(&w.dispatch);
    svc_state_t svc_state = { .w = &w };
    pw_service_t svc = {
        .proto = PW_PROTO_TCP,
        .port = (uint16_t)cfg->port,
        .svc_state = &svc_state,
        .on_open = tls_on_open,
        .on_data = tls_on_data,
        .on_close = tls_on_close,
    };
    if (pw_dispatch_register(&w.dispatch, &svc) != 0) {
        metal_die("tls_worker_main: dispatch register failed");
    }
    if (tcp_attach_dispatch(&w.stack, local_ip, &w.dispatch) != 0) {
        metal_die("tls_worker_main: tcp_attach_dispatch failed");
    }

    emit_ctx_t emit_ctx = { .af = &w.af };
    metal_log("worker %d ready: listen=:%d if=%s backend=tls cert=%s key=%s",
              cfg->worker_index, cfg->port, cfg->tls_ifname,
              cfg->tls_cert_path, cfg->tls_key_path);

    uint64_t last_tick_ms = 0;
    uint8_t frame[2048];
    for (;;) {
        const uint8_t* ip = NULL;
        size_t ip_len = 0;
        if (af_packet_recv(&w.af, frame, sizeof(frame), &ip, &ip_len) == 0) {
            tcp_seg_t seg;
            if (ip_tcp_parse(ip, ip_len, &seg) == 0) {
                uint64_t now = (uint64_t)metal_now_ms();
                tcp_input_at(&w.stack, &seg, now, NULL, NULL, emit_seg, &emit_ctx);
            }
        }
        uint64_t now = (uint64_t)metal_now_ms();
        if (now - last_tick_ms >= 10) {
            tcp_tick(&w.stack, now, emit_seg, &emit_ctx);
            last_tick_ms = now;
        }
    }
}
