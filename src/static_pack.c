/* static_pack.c — serve static content straight from picowal cards,
 * bypassing the on-disk wwwroot tree. See static_pack.h for the protocol. */

#include "static_pack.h"
#include "security_headers.h"
#include "mime.h"

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
 * convention). Returns false on a malformed (non-decimal) segment. */
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
    if (i < rest_len && rest[i] == '.') {
        *out_ext = rest + i;
        *out_ext_len = rest_len - i;
    } else {
        *out_ext = NULL;
        *out_ext_len = 0;
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

    if (method == M_PUT || method == M_DELETE) {
        if (!api_require_pw_auth(cookie, cookie_len, has_pw_auth_header,
                                 write_token, write_token_len, resp)) return;
    }

    if (method == M_PUT) {
        if (body_len == 0 || body_len > PICOWAL_DATA_MAX) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        if (picowal_db_put_key(api_picowal_db(), key, body, (uint32_t)body_len, false) != 0) {
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
