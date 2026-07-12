/* pico_route.c — dynamic HTTP routes rendered by PicoScript bytecode
 * loaded from picowal. See pico_route.h for the protocol. */

#include "pico_route.h"
#include "security_headers.h"
#include "pico/picovm.h"
#include "pico/pico_hooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define PICO_ROUTE_BYTECODE_CAP  (PICOWAL_DATA_MAX / 4U)  /* words */
#define PICO_ROUTE_ARENA_BYTES   (32U * 1024U)

static uint16_t g_card = 0;
static char     g_prefix[64] = {0};
static size_t   g_prefix_len = 0;
static bool     g_enabled = false;

bool pico_route_enabled(void) { return g_enabled; }

static int pico_route_storage_hook(pv_ctx *ctx, int hook, int rd, int rs1, int rs2);

static bool valid_prefix(const char* prefix, size_t cap) {
    size_t pl = prefix ? strlen(prefix) : 0;
    if (pl < 2 || pl >= cap) {
        fprintf(stderr, "pico_route: invalid --picowal-code-prefix (must be 2..%zu chars, start and end with '/')\n", cap - 1);
        return false;
    }
    if (prefix[0] != '/' || prefix[pl - 1] != '/') {
        fprintf(stderr, "pico_route: invalid --picowal-code-prefix '%s' (must start and end with '/')\n", prefix);
        return false;
    }
    return true;
}

bool pico_route_init(uint16_t router_card, const char* prefix) {
    g_enabled = false;
    if (!api_picowal_db()) {
        fprintf(stderr, "pico_route: requires --picowal-device to be configured first\n");
        return false;
    }
    if (!valid_prefix(prefix, sizeof(g_prefix))) return false;
    if (router_card > PICOWAL_CARD_MAX) {
        fprintf(stderr, "pico_route: --picowal-code-card out of range (0..%u)\n", PICOWAL_CARD_MAX);
        return false;
    }
    size_t pl = strlen(prefix);
    memcpy(g_prefix, prefix, pl + 1);
    g_prefix_len = pl;
    g_card = router_card;
    g_enabled = true;
    pv_storage_hook = pico_route_storage_hook;
    return true;
}

bool pico_route_path_matches(const char* path, size_t path_len) {
    return g_enabled &&
           path_len >= g_prefix_len &&
           memcmp(path, g_prefix, g_prefix_len) == 0;
}

/* -- Storage.* / Search.* bridge: maps the PicoScript pack/card model onto
 * the *same* open picowal volume the /wal/ REST API uses. rs1/rs2 are
 * register indices (per pv_storage_fn); pv_host2 (used by toC-emitted
 * code) and the bytecode NOOP-hook path both place operands in
 * ctx->regs[1]/ctx->regs[2] before calling the host, so this reads them
 * the same way api_blob/pico's earlier host-file backend did. -- */
static uint32_t span_ptr(pv_ctx *ctx, int h) { return (h > 0 && h < ctx->span_count) ? ctx->span_ptr[h] : 0; }
static int32_t  span_len(pv_ctx *ctx, int h) { return (h > 0 && h < ctx->span_count) ? ctx->span_len[h] : 0; }
static int span_from_bytes(pv_ctx *ctx, const uint8_t *data, int32_t len) {
    if (!ctx->mem || len <= 0 || (uint64_t)ctx->arena_top + (uint32_t)len > (uint64_t)ctx->mem_size) return 0;
    for (int32_t i = 0; i < len; i++) ctx->mem[ctx->arena_top + (uint32_t)i] = data[i];
    if (ctx->span_count >= PV_MAX_SPANS) return 0;
    int h = ctx->span_count++;
    ctx->span_ptr[h] = ctx->arena_top;
    ctx->span_len[h] = len;
    ctx->arena_top += (uint32_t)len;
    return h;
}

static int pico_route_storage_hook(pv_ctx *ctx, int hook, int rd, int rs1, int rs2) {
    picowal_db_t *db = api_picowal_db();
    if (!db) return 0;

    switch (hook) {
    case PV_HOOK_STORAGE_ADDCARD: {
        uint16_t pack = (uint16_t)ctx->regs[rs1];
        int h = ctx->regs[rs2];
        uint32_t p = span_ptr(ctx, h);
        int32_t n = span_len(ctx, h);
        uint8_t buf[PICOWAL_DATA_MAX];
        if (n > (int32_t)sizeof(buf)) n = sizeof(buf);
        for (int32_t i = 0; i < n; i++) buf[i] = ctx->mem[p + (uint32_t)i];
        /* Auto-increment: linear-probe from record 0 for the first free slot.
         * O(n) worst case but bounded by PICOWAL_RECORD_MAX in practice;
         * app-level packs are expected to be modest in size. */
        for (uint32_t rec = 0; rec <= PICOWAL_RECORD_MAX; rec++) {
            uint32_t key;
            if (!picowal_db_pack_key(pack, rec, &key)) break;
            if (!picowal_db_exists_key(db, key)) {
                ctx->regs[rd] = (picowal_db_put_key(db, key, buf, (uint32_t)n, true) == 0) ? (int32_t)rec : -1;
                return 1;
            }
        }
        ctx->regs[rd] = -1;
        return 1;
    }
    case PV_HOOK_STORAGE_UPDATECARD: {
        /* Storage.UpdateCard(pack, card_id, data) is compiled as a 3-register
         * op (see picoscript_lang.py _compile_host_hook: AddCard/UpdateCard/
         * PatchCard/ReadCard/QueryCard all take rs1,rs2,"rd" positionally from
         * the 3 source args). Unlike AddCard (rs1=pack, rs2=data, rd=out
         * record), UpdateCard's 3rd arg is the *data* span itself, not an
         * output -- there's no 4th register to hold both data-in and a
         * separate result-out, so the result is written back in place into
         * the same slot the data span came in on (rd). */
        uint16_t pack = (uint16_t)ctx->regs[rs1];
        uint32_t rec = (uint32_t)ctx->regs[rs2];
        int h = ctx->regs[rd];
        uint32_t p = span_ptr(ctx, h);
        int32_t n = span_len(ctx, h);
        uint32_t key;
        if (!picowal_db_pack_key(pack, rec, &key)) { ctx->regs[rd] = 0; return 1; }
        uint8_t buf[PICOWAL_DATA_MAX];
        if (n > (int32_t)sizeof(buf)) n = sizeof(buf);
        for (int32_t i = 0; i < n; i++) buf[i] = ctx->mem[p + (uint32_t)i];
        ctx->regs[rd] = (picowal_db_put_key(db, key, buf, (uint32_t)n, true) == 0) ? 1 : 0;
        return 1;
    }
    case PV_HOOK_STORAGE_DELETECARD: {
        uint16_t pack = (uint16_t)ctx->regs[rs1];
        uint32_t rec = (uint32_t)ctx->regs[rs2];
        uint32_t key;
        if (!picowal_db_pack_key(pack, rec, &key)) { ctx->regs[rd] = 0; return 1; }
        ctx->regs[rd] = (picowal_db_delete_key(db, key) == 0) ? 1 : 0;
        return 1;
    }
    case PV_HOOK_STORAGE_READCARD: {
        uint16_t pack = (uint16_t)ctx->regs[rs1];
        uint32_t rec = (uint32_t)ctx->regs[rs2];
        uint32_t key;
        if (!picowal_db_pack_key(pack, rec, &key)) { ctx->regs[rd] = 0; return 1; }
        uint8_t buf[PICOWAL_DATA_MAX];
        int n = picowal_db_get_key(db, key, buf, sizeof(buf));
        ctx->regs[rd] = (n < 0) ? 0 : span_from_bytes(ctx, buf, n);
        return 1;
    }
    default:
        return 0; /* not a storage hook we handle; falls through as a no-op */
    }
}

static void resp_status_only(api_resp_t* r, int status, const char* reason) {
    r->status = status;
    r->head_len = (size_t)snprintf(r->head, sizeof(r->head),
                                   "HTTP/1.1 %d %s\r\n"
                                   "Server: picoweb\r\n"
                                   "Content-Length: 0\r\n"
                                   PICOWEB_SECURITY_HEADERS,
                                   status, reason);
}

static void resp_text_error(api_resp_t* r, int status, const char* reason, const char* body) {
    size_t blen = body ? strlen(body) : 0;
    r->status = status;
    r->head_len = (size_t)snprintf(r->head, sizeof(r->head),
                                   "HTTP/1.1 %d %s\r\n"
                                   "Server: picoweb\r\n"
                                   "Content-Type: text/plain; charset=utf-8\r\n"
                                   "Content-Length: %zu\r\n"
                                   PICOWEB_SECURITY_HEADERS,
                                   status, reason, blen);
    if (blen) {
        r->body = (char*)malloc(blen);
        if (r->body) {
            memcpy(r->body, body, blen);
            r->body_len = blen;
            r->body_owned = true;
        }
    }
}

static const char* method_name(http_method_t m) {
    switch (m) {
    case M_GET: return "GET"; case M_HEAD: return "HEAD"; case M_POST: return "POST";
    case M_PUT: return "PUT"; case M_DELETE: return "DELETE"; case M_OPTIONS: return "OPTIONS";
    default: return "";
    }
}

void pico_route_dispatch(http_method_t method,
                         const char* path, size_t path_len,
                         const char* body, size_t body_len,
                         const char* cookie, size_t cookie_len,
                         bool has_pw_auth_header,
                         const char* write_token, size_t write_token_len,
                         api_resp_t* resp) {
    picowal_db_t *db = api_picowal_db();
    uint32_t key;
    if (!db || !picowal_db_pack_key(g_card, 0, &key)) {
        resp_status_only(resp, 500, "Internal Server Error");
        return;
    }

    /* PUT to the bare prefix publishes new bytecode to record 0, bypassing
     * /wal/'s JSON-schema validation (this is a raw binary blob, not JSON).
     * Any other path with any method falls through to executing the
     * current program (it decides its own routing via Req.Path()). */
    bool is_deploy = (method == M_PUT) && (path_len == g_prefix_len);
    if (is_deploy) {
        if (!api_require_pw_auth(cookie, cookie_len, has_pw_auth_header,
                                 write_token, write_token_len, resp)) return;
        if (body_len == 0 || body_len > PICOWAL_DATA_MAX || (body_len % 4) != 0) {
            resp_text_error(resp, 400, "Bad Request",
                            "expected a non-empty raw bytecode blob, word-aligned (len % 4 == 0)\n");
            return;
        }
        int fault_pc = 0, fault_detail = 0;
        if (pv_verify((const uint32_t*)body, (int)(body_len / 4), &fault_pc, &fault_detail) != 0) {
            char msg[128];
            snprintf(msg, sizeof(msg), "bytecode verify failed at pc=%d detail=%d\n", fault_pc, fault_detail);
            resp_text_error(resp, 400, "Bad Request", msg);
            return;
        }
        if (picowal_db_put_key(db, key, body, (uint32_t)body_len, false) != 0) {
            if (errno == EROFS) {
                resp_text_error(resp, 503, "Service Unavailable", "read replica: writes must go to the primary\n");
                return;
            }
            if (errno == ENOSPC) {
                resp_text_error(resp, 507, "Insufficient Storage", "wal volume full\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "pico_route deploy write failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    /* Fetch and re-verify the router bytecode on every request: publishing
     * new code is a plain picowal write to (g_card, record 0), no restart.
     * Heap-allocated (not static) -- picoweb runs multiple worker threads
     * concurrently and this path must be race-free across them. */
    uint32_t *words = (uint32_t*)malloc(PICO_ROUTE_BYTECODE_CAP * sizeof(uint32_t));
    if (!words) { resp_status_only(resp, 500, "Internal Server Error"); return; }
    int nbytes = picowal_db_get_key(db, key, words, PICO_ROUTE_BYTECODE_CAP * sizeof(uint32_t));
    if (nbytes <= 0 || (nbytes % 4) != 0) {
        free(words);
        resp_status_only(resp, 404, "Not Found");
        return;
    }
    int nwords = nbytes / 4;
    int fault_pc = 0, fault_detail = 0;
    if (pv_verify(words, nwords, &fault_pc, &fault_detail) != 0) {
        fprintf(stderr, "pico_route: bytecode verify failed at pc=%d detail=%d\n", fault_pc, fault_detail);
        free(words);
        resp_status_only(resp, 500, "Internal Server Error");
        return;
    }

    uint8_t *arena = (uint8_t*)malloc(PICO_ROUTE_ARENA_BYTES);
    if (!arena) { free(words); resp_status_only(resp, 500, "Internal Server Error"); return; }

    pv_ctx ctx;
    pv_init(&ctx);
    ctx.mem = arena;
    ctx.mem_size = PICO_ROUTE_ARENA_BYTES;
    ctx.req_method = method_name(method);
    ctx.req_method_len = (int)strlen(ctx.req_method);
    ctx.req_path = path;
    ctx.req_path_len = (int)path_len;
    ctx.req_body = body;
    ctx.req_body_len = (int)body_len;
    /* Synthesize a minimal raw header block so Req.Header("cookie") works;
     * see pico_route.h for why full header passthrough isn't wired yet. */
    char hdrbuf[512];
    int hlen = 0;
    if (cookie && cookie_len > 0 && cookie_len + 32 < sizeof(hdrbuf)) {
        hlen = snprintf(hdrbuf, sizeof(hdrbuf), "cookie: %.*s\r\n", (int)cookie_len, cookie);
    }
    ctx.req_headers = hdrbuf;
    ctx.req_headers_len = hlen;

    pv_vm_run(&ctx, words, nwords);
    free(words);

    if (ctx.fault != PV_FAULT_NONE || ctx.http_status < 100) {
        free(arena);
        resp_status_only(resp, 500, "Internal Server Error");
        return;
    }

    char *out_copy = (char*)malloc((size_t)ctx.out_len);
    if (ctx.out_len > 0 && !out_copy) {
        free(arena);
        resp_status_only(resp, 500, "Internal Server Error");
        return;
    }
    if (ctx.out_len > 0) memcpy(out_copy, ctx.out, (size_t)ctx.out_len);

    resp->status = ctx.http_status;
    resp->head_len = (size_t)snprintf(resp->head, sizeof(resp->head),
                                      "HTTP/1.1 %d PicoScript\r\n"
                                      "Server: picoweb\r\n"
                                      "Content-Type: application/octet-stream\r\n"
                                      "Content-Length: %d\r\n"
                                      PICOWEB_SECURITY_HEADERS
                                      "Cache-Control: no-store\r\n",
                                      ctx.http_status, ctx.out_len);
    if (method == M_HEAD || ctx.out_len == 0) {
        free(out_copy);
    } else {
        resp->body = out_copy;
        resp->body_len = (size_t)ctx.out_len;
        resp->body_owned = true;
    }
    free(arena);
}
