/* static_pack.c — serve static content straight from picowal cards,
 * bypassing the on-disk wwwroot tree. See static_pack.h for the protocol. */

#include "static_pack.h"
#include "security_headers.h"
#include "mime.h"
#include "picowal_partition.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define STATIC_PACK_BODY_CAP PICOWAL_DATA_MAX

static uint16_t g_card = 0;
static char     g_prefix[64] = {0};
static size_t   g_prefix_len = 0;
static bool     g_enabled = false;

const char* static_pack_prefix(void) { return g_enabled ? g_prefix : ""; }

bool static_pack_enabled(void) { return g_enabled; }

static bool valid_prefix(const char* prefix, size_t cap) {
    size_t pl = prefix ? strlen(prefix) : 0;
    if (pl < 2 || pl >= cap) {
        fprintf(stderr, "static_pack: invalid --picowal-static-prefix (must be 2..%zu chars, start and end with '/')\n", cap - 1);
        return false;
    }
    if (prefix[0] != '/' || prefix[pl - 1] != '/') {
        fprintf(stderr, "static_pack: invalid --picowal-static-prefix '%s' (must start and end with '/')\n", prefix);
        return false;
    }
    return true;
}

bool static_pack_init(uint16_t card, const char* prefix) {
    g_enabled = false;
    if (!api_picowal_db()) {
        fprintf(stderr, "static_pack: requires --picowal-device to be configured first\n");
        return false;
    }
    if (!valid_prefix(prefix, sizeof(g_prefix))) return false;
    if (card > PICOWAL_CARD_MAX) {
        fprintf(stderr, "static_pack: --picowal-static-card out of range (0..%u)\n", PICOWAL_CARD_MAX);
        return false;
    }
    size_t pl = strlen(prefix);
    memcpy(g_prefix, prefix, pl + 1);
    g_prefix_len = pl;
    g_card = card;
    g_enabled = true;
    return true;
}

bool static_pack_path_matches(const char* path, size_t path_len) {
    return g_enabled &&
           path_len >= g_prefix_len &&
           memcmp(path, g_prefix, g_prefix_len) == 0;
}

/* Parse the decimal record id from the path segment right after the
 * prefix, stopping at '/' or '.'. Empty segment -> record 0 (index
 * convention). Returns false on a malformed (non-decimal) segment.
 *
 * Two trailing forms are supported for MIME sniffing, both mapping onto
 * the SAME record (the trailing filename is never part of the picowal
 * key, only used to pick a Content-Type via mime.c):
 *   {record}.ext          e.g. "/site/0.html"       -> record 0, ext ".html"
 *   {record}/filename.ext e.g. "/site/0/index.html" -> record 0, ext ".html"
 * The second form lets an operator publish a small multi-file bundle
 * ("/site/0/index.html", "/site/1/app.js", ...) with human-readable
 * filenames while storage stays a flat record-per-file scheme. */
static bool parse_record(const char* rest, size_t rest_len, uint32_t* out_record,
                         const char** out_ext, size_t* out_ext_len) {
    size_t i = 0;
    uint64_t rec = 0;
    bool any = false;
    while (i < rest_len && rest[i] != '/' && rest[i] != '.') {
        if (!isdigit((unsigned char)rest[i])) return false;
        rec = rec * 10 + (uint64_t)(rest[i] - '0');
        if (rec > PICOWAL_RECORD_MAX) return false;
        any = true;
        i++;
    }
    *out_record = any ? (uint32_t)rec : 0;
    *out_ext = NULL;
    *out_ext_len = 0;

    if (i < rest_len && rest[i] == '.') {
        /* "{record}.ext" -- extension is the remainder of the segment. */
        *out_ext = rest + i;
        *out_ext_len = rest_len - i;
        return true;
    }
    if (i < rest_len && rest[i] == '/') {
        /* "{record}/filename.ext" -- extension comes from the LAST '.' in
         * the trailing filename component (not part of the key). */
        const char* fname = rest + i + 1;
        size_t fname_len = rest_len - (i + 1);
        const char* dot = NULL;
        for (size_t j = 0; j < fname_len; j++) {
            if (fname[j] == '.') dot = fname + j;
        }
        if (dot) {
            *out_ext = dot;
            *out_ext_len = (size_t)((fname + fname_len) - dot);
        }
    }
    return true;
}

static void resp_status_only(api_resp_t* r, int status, const char* reason) {
    r->status = status;
    r->head_len = (size_t)snprintf(r->head, sizeof(r->head),
                                   "HTTP/1.1 %d %s\r\n"
                                   "Server: picoweb\r\n"
                                   "Content-Length: 0\r\n"
                                   PICOWEB_SECURITY_HEADERS
                                   "Cache-Control: no-store\r\n",
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
                                   PICOWEB_SECURITY_HEADERS
                                   "Cache-Control: no-store\r\n",
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

void static_pack_dispatch(http_method_t method,
                          const char* path, size_t path_len,
                          const char* body, size_t body_len,
                          const char* cookie, size_t cookie_len,
                          bool has_pw_auth_header,
                          const char* write_token, size_t write_token_len,
                          const char* tenant_id, size_t tenant_id_len,
                          bool is_partition_hop,
                          api_resp_t* resp) {
    if (method != M_GET && method != M_HEAD &&
        method != M_PUT && method != M_DELETE) {
        resp_status_only(resp, 405, "Method Not Allowed");
        return;
    }

    const char* rest = path + g_prefix_len;
    size_t rest_len = path_len - g_prefix_len;
    uint32_t record;
    const char* ext;
    size_t ext_len;
    if (!parse_record(rest, rest_len, &record, &ext, &ext_len)) {
        resp_status_only(resp, 400, "Bad Request");
        return;
    }

    uint32_t key;
    if (!picowal_db_pack_key((uint16_t)g_card, record, &key)) {
        resp_status_only(resp, 400, "Bad Request");
        return;
    }

    /* Authenticate mutations before resolving or contacting a remote owner.
     * Besides keeping the route uniformly protected, this prevents an
     * unauthenticated request from reaching the partition transport, whose
     * internal machine credential is intentionally available for trusted
     * server-to-server forwarding. */
    if (method == M_PUT || method == M_DELETE) {
        if (!api_require_pw_auth(cookie, cookie_len, has_pw_auth_header,
                                 write_token, write_token_len, resp)) return;
    }

    /* Partition-aware forwarding: static content isn't assumed replicated
     * across every node in the pool (each node's picowal volume is its own
     * shard), so a non-owner node must forward GET/HEAD too, not just
     * mutations -- unlike /wal/'s REST API, which assumes the node pool
     * itself is fully replicated and only proxies writes. Skipped when
     * this request is itself an inbound partition-hop (X-PW-Partition-Hop)
     * to avoid forwarding loops. */
    if (!is_partition_hop && picowal_partition_enabled()) {
        uint32_t vpart = picowal_partition_of_key(key);
        char owner[PICOWAL_PARTITION_NODE_ID_MAX];
        if (picowal_partition_owner(tenant_id, tenant_id_len, vpart, owner, sizeof(owner)) &&
            !picowal_partition_owner_is_self(owner)) {
            if (picowal_partition_mode_is_proxy()) {
                picowal_partition_proxy(owner, vpart, method, path, path_len,
                                        body, body_len,
                                        write_token, write_token_len,
                                        cookie, cookie_len, resp);
            } else {
                picowal_partition_redirect(owner, vpart, path, path_len, resp);
            }
            return;
        }
    }

    if (method == M_PUT) {
        if (body_len == 0 || body_len > PICOWAL_DATA_MAX) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        if (picowal_db_put_key(api_picowal_db(), key, body, (uint32_t)body_len, false) != 0) {
            if (errno == EROFS) {
                resp_text_error(resp, 503, "Service Unavailable", "read replica: writes must go to the primary\n");
                return;
            }
            if (errno == ENOSPC) {
                resp_text_error(resp, 507, "Insufficient Storage", "wal volume full\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "static-pack write failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    if (method == M_DELETE) {
        if (picowal_db_delete_key(api_picowal_db(), key) != 0) {
            if (errno == EROFS) {
                resp_text_error(resp, 503, "Service Unavailable", "read replica: writes must go to the primary\n");
                return;
            }
            if (errno == ENOENT) { resp_status_only(resp, 404, "Not Found"); return; }
            resp_text_error(resp, 500, "Internal Server Error", "static-pack delete failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    char* buf = (char*)malloc(STATIC_PACK_BODY_CAP);
    if (!buf) { resp_status_only(resp, 500, "Internal Server Error"); return; }
    int n = picowal_db_get_key(api_picowal_db(), key, buf, STATIC_PACK_BODY_CAP);
    if (n < 0) { free(buf); resp_status_only(resp, 404, "Not Found"); return; }

    const char* mime = ext_len > 0 ? mime_lookup(ext, ext_len) : NULL;
    if (!mime) mime = "application/octet-stream";

    resp->status = 200;
    resp->head_len = (size_t)snprintf(resp->head, sizeof(resp->head),
                                      "HTTP/1.1 200 OK\r\n"
                                      "Server: picoweb\r\n"
                                      "Content-Type: %s\r\n"
                                      "Content-Length: %d\r\n"
                                      PICOWEB_SECURITY_HEADERS
                                      "Cache-Control: no-cache\r\n",
                                      mime, n);
    if (method == M_HEAD) { free(buf); return; }
    resp->body = buf;
    resp->body_len = (size_t)n;
    resp->body_owned = true;
}
