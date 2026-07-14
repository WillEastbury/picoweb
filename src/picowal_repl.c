/* picowal_repl.c — primary-side segment-aware log replication feed. See
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

/* Parses one decimal path segment, e.g. "123" -> 123. Returns false if
 * empty or malformed (no '/' allowed inside -- caller has already split
 * on '/'). */
static bool parse_u64_segment(const char* p, size_t plen, uint64_t* out) {
    uint64_t v = 0;
    if (plen == 0 || plen > 20) return false;
    for (size_t i = 0; i < plen; i++) {
        char c = p[i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (uint64_t)(c - '0');
    }
    *out = v;
    return true;
}

/* Splits "rest" (already past the route keyword, e.g. "segment/") into
 * two '/'-separated decimal fields, e.g. "3/2" -> (3, 2). Returns false
 * if malformed. */
static bool parse_two_u64(const char* p, size_t plen, uint64_t* a, uint64_t* b) {
    const char* slash = memchr(p, '/', plen);
    if (!slash) return false;
    size_t alen = (size_t)(slash - p);
    size_t blen = plen - alen - 1;
    return parse_u64_segment(p, alen, a) && parse_u64_segment(slash + 1, blen, b);
}

static void resp_json(api_resp_t* r, http_method_t method, const char* body, int blen) {
    r->status = 200;
    r->head_len = (size_t)snprintf(r->head, sizeof(r->head),
                                   "HTTP/1.1 200 OK\r\n"
                                   "Server: picoweb\r\n"
                                   "Content-Type: application/json\r\n"
                                   "Content-Length: %d\r\n"
                                   PICOWEB_SECURITY_HEADERS
                                   "Cache-Control: no-store\r\n",
                                   blen);
    if (method == M_HEAD) return;
    r->body = (char*)malloc((size_t)blen);
    if (r->body) {
        memcpy(r->body, body, (size_t)blen);
        r->body_len = (size_t)blen;
        r->body_owned = true;
    }
}

static void handle_status(http_method_t method, picowal_db_t* db, api_resp_t* resp) {
    uint32_t leading_wal_id = 0;
    uint64_t leading_write_off = 0, segment_bytes = 0, next_seq = 0;
    picowal_db_repl_status(db, &leading_wal_id, &leading_write_off, &segment_bytes, &next_seq);
    char body[220];
    int blen = snprintf(body, sizeof(body),
                        "{\"leading_wal_id\":%u,\"leading_write_off\":%llu,"
                        "\"segment_bytes\":%llu,\"next_seq\":%llu}",
                        leading_wal_id,
                        (unsigned long long)leading_write_off,
                        (unsigned long long)segment_bytes,
                        (unsigned long long)next_seq);
    resp_json(resp, method, body, blen);
}

static void handle_segments(http_method_t method, picowal_db_t* db, api_resp_t* resp) {
    picowal_seg_info_t segs[256];
    uint32_t n = picowal_db_list_segments(db, segs, 256);

    /* Bound: 256 segments * ~64 bytes each + wrapper, generous cap. */
    size_t cap = 256 + (size_t)n * 80;
    char* body = (char*)malloc(cap);
    if (!body) { resp_status_only(resp, 500, "Internal Server Error"); return; }
    size_t off = 0;
    off += (size_t)snprintf(body + off, cap - off, "{\"segments\":[");
    for (uint32_t i = 0; i < n; i++) {
        off += (size_t)snprintf(body + off, cap - off,
                                "%s{\"seg_id\":%u,\"generation\":%u,\"sealed\":%s,\"bytes\":%llu}",
                                i ? "," : "",
                                segs[i].seg_id, segs[i].generation,
                                segs[i].sealed ? "true" : "false",
                                (unsigned long long)segs[i].bytes);
    }
    off += (size_t)snprintf(body + off, cap - off, "]}");
    resp_json(resp, method, body, (int)off);
    free(body);
}

static void handle_segment_fetch(http_method_t method, picowal_db_t* db,
                                 const char* rest, size_t rest_len, api_resp_t* resp) {
    uint64_t id64 = 0, gen64 = 0;
    if (!parse_two_u64(rest, rest_len, &id64, &gen64) || id64 > UINT32_MAX || gen64 > UINT32_MAX) {
        resp_text_error(resp, 400, "Bad Request", "malformed segment/ID/GENERATION\n");
        return;
    }

    char* buf = (char*)malloc(PICOWAL_REPL_CHUNK_MAX);
    if (!buf) { resp_status_only(resp, 500, "Internal Server Error"); return; }
    uint32_t buf_len = PICOWAL_REPL_CHUNK_MAX;
    if (picowal_db_repl_read_segment(db, (uint32_t)id64, (uint32_t)gen64, buf, &buf_len) != 0) {
        free(buf);
        if (errno == ENOENT) {
            resp_text_error(resp, 404, "Not Found", "no such segment\n");
        } else if (errno == ESTALE) {
            resp_text_error(resp, 410, "Gone", "generation is stale; re-list segments\n");
        } else if (errno == EROFS) {
            resp_text_error(resp, 409, "Conflict", "segment is currently leading; use stream instead\n");
        } else {
            resp_text_error(resp, 400, "Bad Request", "invalid segment fetch\n");
        }
        return;
    }

    resp->status = 200;
    resp->head_len = (size_t)snprintf(resp->head, sizeof(resp->head),
                                      "HTTP/1.1 200 OK\r\n"
                                      "Server: picoweb\r\n"
                                      "Content-Type: application/octet-stream\r\n"
                                      "Content-Length: %u\r\n"
                                      PICOWEB_SECURITY_HEADERS
                                      "Cache-Control: no-store\r\n",
                                      buf_len);
    if (method == M_HEAD) { free(buf); return; }
    resp->body = buf;
    resp->body_len = buf_len;
    resp->body_owned = true;
}

static void handle_stream(http_method_t method, picowal_db_t* db,
                          const char* rest, size_t rest_len, api_resp_t* resp) {
    uint64_t id64 = 0, off64 = 0;
    if (!parse_two_u64(rest, rest_len, &id64, &off64) || id64 > UINT32_MAX) {
        resp_text_error(resp, 400, "Bad Request", "malformed stream/ID/OFFSET\n");
        return;
    }

    char* buf = (char*)malloc(PICOWAL_REPL_CHUNK_MAX);
    if (!buf) { resp_status_only(resp, 500, "Internal Server Error"); return; }
    uint32_t chunk_len = PICOWAL_REPL_CHUNK_MAX;
    if (picowal_db_repl_read_leading(db, (uint32_t)id64, off64, buf, &chunk_len) != 0) {
        free(buf);
        if (errno == EINVAL) {
            resp_text_error(resp, 409, "Conflict",
                            "segment is no longer leading (it was sealed by rotation); "
                            "fetch it wholesale via /segment/{id}/{gen} instead\n");
        } else if (errno == ERANGE) {
            resp_text_error(resp, 416, "Range Not Satisfiable", "offset is beyond current write_off\n");
        } else {
            resp_text_error(resp, 400, "Bad Request", "invalid stream request\n");
        }
        return;
    }

    uint32_t leading_wal_id = 0;
    uint64_t leading_write_off = 0;
    picowal_db_repl_status(db, &leading_wal_id, &leading_write_off, NULL, NULL);

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
                                      (unsigned long long)off64,
                                      chunk_len,
                                      (unsigned long long)leading_write_off);
    if (method == M_HEAD) { free(buf); return; }
    resp->body = buf;
    resp->body_len = chunk_len;
    resp->body_owned = true;
}

static void handle_ack(picowal_db_t* db, const char* rest, size_t rest_len,
                       const char* body, size_t body_len, api_resp_t* resp) {
    uint64_t id64 = 0, off64 = 0;
    if (!parse_two_u64(rest, rest_len, &id64, &off64) || id64 > UINT32_MAX) {
        resp_text_error(resp, 400, "Bad Request", "malformed ack/ID/OFFSET\n");
        return;
    }
    char replica_id[64];
    size_t n = body_len < sizeof(replica_id) - 1 ? body_len : sizeof(replica_id) - 1;
    /* Trim to the first line/whitespace; a bare id is all we expect. */
    size_t rn = 0;
    for (; rn < n; rn++) {
        char c = body[rn];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') break;
        replica_id[rn] = c;
    }
    replica_id[rn] = '\0';
    picowal_db_repl_ack(db, rn ? replica_id : "replica", (uint32_t)id64, off64);
    resp_status_only(resp, 204, "No Content");
}

void picowal_repl_dispatch(http_method_t method,
                           const char* path, size_t path_len,
                           const char* body, size_t body_len,
                           const char* write_token, size_t write_token_len,
                           api_resp_t* resp) {
    if (!api_require_write_token(write_token, write_token_len, resp)) return;

    picowal_db_t* db = api_picowal_db();
    if (!db) { resp_status_only(resp, 500, "Internal Server Error"); return; }

    const char* rest = path + g_prefix_len;
    size_t rest_len = path_len - g_prefix_len;

    if (rest_len == 6 && memcmp(rest, "status", 6) == 0) {
        if (method != M_GET && method != M_HEAD) { resp_status_only(resp, 405, "Method Not Allowed"); return; }
        handle_status(method, db, resp);
        return;
    }
    if (rest_len == 8 && memcmp(rest, "segments", 8) == 0) {
        if (method != M_GET && method != M_HEAD) { resp_status_only(resp, 405, "Method Not Allowed"); return; }
        handle_segments(method, db, resp);
        return;
    }

    static const char k_segment[] = "segment/";
    size_t segment_len = sizeof(k_segment) - 1;
    if (rest_len > segment_len && memcmp(rest, k_segment, segment_len) == 0) {
        if (method != M_GET && method != M_HEAD) { resp_status_only(resp, 405, "Method Not Allowed"); return; }
        handle_segment_fetch(method, db, rest + segment_len, rest_len - segment_len, resp);
        return;
    }

    static const char k_stream[] = "stream/";
    size_t stream_len = sizeof(k_stream) - 1;
    if (rest_len > stream_len && memcmp(rest, k_stream, stream_len) == 0) {
        if (method != M_GET && method != M_HEAD) { resp_status_only(resp, 405, "Method Not Allowed"); return; }
        handle_stream(method, db, rest + stream_len, rest_len - stream_len, resp);
        return;
    }

    static const char k_ack[] = "ack/";
    size_t ack_len = sizeof(k_ack) - 1;
    if (rest_len > ack_len && memcmp(rest, k_ack, ack_len) == 0) {
        if (method != M_POST) { resp_status_only(resp, 405, "Method Not Allowed"); return; }
        handle_ack(db, rest + ack_len, rest_len - ack_len, body, body_len, resp);
        return;
    }

    resp_status_only(resp, 404, "Not Found");
}
