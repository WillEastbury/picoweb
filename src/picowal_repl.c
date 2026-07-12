/* picowal_repl.c — primary-side raw log replication feed. See
 * picowal_repl.h for the wire protocol. */

#include "picowal_repl.h"
#include "picowal_db.h"
#include "security_headers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static char   g_prefix[64] = {0};
static size_t g_prefix_len = 0;
static bool   g_enabled = false;

bool picowal_repl_enabled(void) { return g_enabled; }

static bool valid_prefix(const char* prefix, size_t cap) {
    size_t pl = prefix ? strlen(prefix) : 0;
    if (pl < 2 || pl >= cap) {
        fprintf(stderr, "picowal_repl: invalid --picowal-repl-prefix (must be 2..%zu chars, start and end with '/')\n", cap - 1);
        return false;
    }
    if (prefix[0] != '/' || prefix[pl - 1] != '/') {
        fprintf(stderr, "picowal_repl: invalid --picowal-repl-prefix '%s' (must start and end with '/')\n", prefix);
        return false;
    }
    return true;
}

bool picowal_repl_init(const char* prefix) {
    g_enabled = false;
    if (!api_picowal_db()) {
        fprintf(stderr, "picowal_repl: requires --picowal-device to be configured first\n");
        return false;
    }
    if (!valid_prefix(prefix, sizeof(g_prefix))) return false;
    size_t pl = strlen(prefix);
    memcpy(g_prefix, prefix, pl + 1);
    g_prefix_len = pl;
    g_enabled = true;
    return true;
}

bool picowal_repl_path_matches(const char* path, size_t path_len) {
    return g_enabled &&
           path_len >= g_prefix_len &&
           memcmp(path, g_prefix, g_prefix_len) == 0;
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

/* Parses the decimal offset following the "stream/" path segment, e.g.
 * "stream/512" -> 512. Returns false (leaving *out unset) if absent or
 * malformed. Path-segment based (not a query string: http_parse() strips
 * '?...' before routing ever sees the path, so the offset travels as a
 * path component instead). */
static bool parse_from_segment(const char* p, size_t plen, uint64_t* out) {
    uint64_t v = 0;
    if (plen == 0) return false;
    for (size_t i = 0; i < plen; i++) {
        char c = p[i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (uint64_t)(c - '0');
    }
    *out = v;
    return true;
}

void picowal_repl_dispatch(http_method_t method,
                           const char* path, size_t path_len,
                           const char* write_token, size_t write_token_len,
                           api_resp_t* resp) {
    if (method != M_GET && method != M_HEAD) {
        resp_status_only(resp, 405, "Method Not Allowed");
        return;
    }
    if (!api_require_write_token(write_token, write_token_len, resp)) return;

    picowal_db_t* db = api_picowal_db();
    if (!db) { resp_status_only(resp, 500, "Internal Server Error"); return; }

    const char* rest = path + g_prefix_len;
    size_t rest_len = path_len - g_prefix_len;

    if (rest_len == 6 && memcmp(rest, "status", 6) == 0) {
        uint64_t write_off = 0, volume_bytes = 0, next_seq = 0;
        picowal_db_repl_status(db, &write_off, &volume_bytes, &next_seq);
        char body[160];
        int blen = snprintf(body, sizeof(body),
                            "{\"write_off\":%llu,\"volume_bytes\":%llu,"
                            "\"next_seq\":%llu,\"sector_size\":512}",
                            (unsigned long long)write_off,
                            (unsigned long long)volume_bytes,
                            (unsigned long long)next_seq);
        resp->status = 200;
        resp->head_len = (size_t)snprintf(resp->head, sizeof(resp->head),
                                          "HTTP/1.1 200 OK\r\n"
                                          "Server: picoweb\r\n"
                                          "Content-Type: application/json\r\n"
                                          "Content-Length: %d\r\n"
                                          PICOWEB_SECURITY_HEADERS
                                          "Cache-Control: no-store\r\n",
                                          blen);
        if (method == M_HEAD) return;
        resp->body = (char*)malloc((size_t)blen);
        if (resp->body) {
            memcpy(resp->body, body, (size_t)blen);
            resp->body_len = (size_t)blen;
            resp->body_owned = true;
        }
        return;
    }

    static const char k_stream[] = "stream/";
    size_t stream_len = sizeof(k_stream) - 1;
    if (rest_len >= stream_len && memcmp(rest, k_stream, stream_len) == 0) {
        uint64_t from_off = 0;
        if (!parse_from_segment(rest + stream_len, rest_len - stream_len, &from_off)) {
            resp_text_error(resp, 400, "Bad Request", "malformed stream/OFFSET\n");
            return;
        }
        if ((from_off % 512) != 0 || from_off < 512) {
            resp_text_error(resp, 400, "Bad Request", "from must be a multiple of 512, >= 512\n");
            return;
        }

        char* buf = (char*)malloc(PICOWAL_REPL_CHUNK_MAX);
        if (!buf) { resp_status_only(resp, 500, "Internal Server Error"); return; }
        uint32_t chunk_len = PICOWAL_REPL_CHUNK_MAX;
        if (picowal_db_repl_read(db, from_off, buf, &chunk_len) != 0) {
            free(buf);
            if (errno == ERANGE) {
                resp_text_error(resp, 416, "Range Not Satisfiable", "from is beyond current write_off\n");
            } else {
                resp_text_error(resp, 400, "Bad Request", "invalid from offset\n");
            }
            return;
        }

        uint64_t write_off = 0;
        picowal_db_repl_status(db, &write_off, NULL, NULL);

        resp->status = 200;
        resp->head_len = (size_t)snprintf(resp->head, sizeof(resp->head),
                                          "HTTP/1.1 200 OK\r\n"
                                          "Server: picoweb\r\n"
                                          "Content-Type: application/octet-stream\r\n"
                                          "Content-Length: %u\r\n"
                                          "X-Picowal-From: %llu\r\n"
                                          "X-Picowal-Chunk-Len: %u\r\n"
                                          "X-Picowal-Write-Off: %llu\r\n"
                                          PICOWEB_SECURITY_HEADERS
                                          "Cache-Control: no-store\r\n",
                                          chunk_len,
                                          (unsigned long long)from_off,
                                          chunk_len,
                                          (unsigned long long)write_off);
        if (method == M_HEAD) { free(buf); return; }
        resp->body = buf;
        resp->body_len = chunk_len;
        resp->body_owned = true;
        return;
    }

    resp_status_only(resp, 404, "Not Found");
}
