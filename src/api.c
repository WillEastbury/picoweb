/* api.c — simple JSON-file CRUD for picoweb. See api.h for protocol. */

#include "api.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/* ----- module config (set once in api_init, read from any worker) ----- */

static char   g_root[512]    = {0};
static size_t g_root_len     = 0;
static char   g_prefix[64]   = {0};
static size_t g_prefix_len   = 0;
static bool   g_enabled      = false;

bool api_enabled(void)              { return g_enabled; }
size_t api_max_request_body(void)   { return API_REQ_BODY_CAP; }

bool api_path_matches(const char* path, size_t path_len) {
    if (!g_enabled || !path) return false;
    if (path_len < g_prefix_len) return false;
    return memcmp(path, g_prefix, g_prefix_len) == 0;
}

void api_init(const char* root_dir, const char* prefix) {
    g_enabled = false;
    if (!root_dir || !root_dir[0] || !prefix || !prefix[0]) return;

    size_t pl = strlen(prefix);
    if (pl < 2 || pl >= sizeof(g_prefix)) {
        fprintf(stderr, "api: invalid --api-prefix (must be 2..%zu chars, start and end with '/')\n",
                sizeof(g_prefix) - 1);
        return;
    }
    if (prefix[0] != '/' || prefix[pl - 1] != '/') {
        fprintf(stderr, "api: invalid --api-prefix '%s' (must start and end with '/')\n", prefix);
        return;
    }
    size_t rl = strlen(root_dir);
    if (rl >= sizeof(g_root) - 1) {
        fprintf(stderr, "api: --api-root path too long (%zu >= %zu)\n", rl, sizeof(g_root));
        return;
    }

    /* mkdir -p the root */
    if (mkdir(root_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "api: cannot create --api-root '%s': %s\n", root_dir, strerror(errno));
        return;
    }
    struct stat st;
    if (stat(root_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "api: --api-root '%s' is not a directory\n", root_dir);
        return;
    }

    memcpy(g_root, root_dir, rl);
    g_root[rl] = '\0';
    /* trim trailing slash so we always join with a single "/" */
    while (rl > 1 && g_root[rl - 1] == '/') { g_root[--rl] = '\0'; }
    g_root_len = rl;

    memcpy(g_prefix, prefix, pl);
    g_prefix[pl] = '\0';
    g_prefix_len = pl;
    g_enabled = true;
}

/* ---------- name validation ---------- */

static bool is_valid_name(const char* s, size_t n) {
    if (n == 0 || n > API_NAME_CAP) return false;
    /* reject ".", ".." outright */
    if ((n == 1 && s[0] == '.') ||
        (n == 2 && s[0] == '.' && s[1] == '.')) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        bool ok = (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

/* Split the path AFTER the prefix into {coll, id}. Returns:
 *    2  -> /api/{coll}/{id}        (id may be empty if trailing slash; treat as 0)
 *    1  -> /api/{coll}             (no id segment)
 *   -1  -> malformed
 *
 * out_coll / out_id are pointers into the original path. Lengths are
 * filled in *coll_len / *id_len. */
static int split_path(const char* path, size_t path_len,
                      const char** out_coll, size_t* coll_len,
                      const char** out_id,   size_t* id_len) {
    if (path_len <= g_prefix_len) return -1;
    const char* p   = path + g_prefix_len;
    size_t      n   = path_len - g_prefix_len;

    /* coll = up to next '/' or end */
    size_t s1 = 0;
    while (s1 < n && p[s1] != '/') s1++;
    if (s1 == 0) return -1;
    *out_coll = p; *coll_len = s1;
    if (s1 == n) { *out_id = NULL; *id_len = 0; return 1; }

    /* skip the '/' after coll */
    size_t i = s1 + 1;
    if (i >= n) {
        /* trailing slash with no id */
        *out_id = NULL; *id_len = 0;
        return 1;
    }
    /* id = up to end; reject any further '/' */
    size_t id_start = i;
    while (i < n) {
        if (p[i] == '/') return -1;
        i++;
    }
    *out_id = p + id_start;
    *id_len = i - id_start;
    return 2;
}

/* Build "<root>/<coll>/<id>.json" into out. Returns out length or -1 on
 * overflow. id may be NULL/0 to build the directory path only. */
static ssize_t build_fs_path(char* out, size_t cap,
                             const char* coll, size_t coll_len,
                             const char* id,   size_t id_len) {
    /* root + '/' + coll + '/' + id + ".json" + NUL */
    size_t need = g_root_len + 1 + coll_len;
    if (id_len > 0) need += 1 + id_len + 5;
    need += 1;
    if (need > cap) return -1;
    size_t n = 0;
    memcpy(out + n, g_root, g_root_len); n += g_root_len;
    out[n++] = '/';
    memcpy(out + n, coll, coll_len); n += coll_len;
    if (id_len > 0) {
        out[n++] = '/';
        memcpy(out + n, id, id_len); n += id_len;
        memcpy(out + n, ".json", 5); n += 5;
    }
    out[n] = '\0';
    return (ssize_t)n;
}

/* ---------- response builders ---------- */

static void resp_status_only(api_resp_t* r, int status, const char* reason) {
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Content-Length: 0\r\n"
                     "Cache-Control: no-store\r\n",
                     status, reason);
    r->head_len = (n > 0) ? (size_t)n : 0;
}

static void resp_text_error(api_resp_t* r, int status, const char* reason,
                            const char* body) {
    size_t blen = body ? strlen(body) : 0;
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Content-Type: text/plain; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n",
                     status, reason, blen);
    r->head_len = (n > 0) ? (size_t)n : 0;
    if (blen) {
        r->body = (char*)malloc(blen);
        if (r->body) {
            memcpy(r->body, body, blen);
            r->body_len = blen;
            r->body_owned = true;
        } else {
            /* OOM: degrade to head-only zero-length */
            r->head_len = 0;
            resp_status_only(r, 500, "Internal Server Error");
        }
    }
}

static void resp_get_body(api_resp_t* r, char* body, size_t blen, bool head_only) {
    r->status = 200;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 200 OK\r\n"
                     "Server: picoweb\r\n"
                     "Content-Type: application/json; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n",
                     blen);
    r->head_len = (n > 0) ? (size_t)n : 0;
    if (head_only) {
        free(body);
        return;
    }
    r->body = body;
    r->body_len = blen;
    r->body_owned = true;
}

static void resp_created(api_resp_t* r,
                         const char* coll, size_t coll_len,
                         const char* id,   size_t id_len) {
    r->status = 201;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 201 Created\r\n"
                     "Server: picoweb\r\n"
                     "Location: %s%.*s/%.*s\r\n"
                     "Content-Length: 0\r\n"
                     "Cache-Control: no-store\r\n",
                     g_prefix,
                     (int)coll_len, coll,
                     (int)id_len, id);
    r->head_len = (n > 0) ? (size_t)n : 0;
}

/* ---------- random id generator (hex32) ---------- */

static bool gen_id(char out[33]) {
    uint8_t raw[16];
    /* getrandom() blocks only if the urandom pool is uninitialised; on
     * any real Linux box at server-start time it returns immediately. */
    ssize_t got = 0;
    while (got < (ssize_t)sizeof(raw)) {
        ssize_t r = getrandom(raw + got, sizeof(raw) - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        got += r;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(raw); i++) {
        out[i * 2 + 0] = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0xf];
    }
    out[32] = '\0';
    return true;
}

/* ---------- file ops ---------- */

/* Read up to API_RESP_BODY_CAP bytes from path into a freshly malloced
 * buffer. Returns:
 *    0  on success (sets *out_buf, *out_len; caller frees buf)
 *   -1  ENOENT
 *   -2  too large (file size > API_RESP_BODY_CAP)
 *   -3  other I/O / OOM
 */
static int read_file_full(const char* path, char** out_buf, size_t* out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return (errno == ENOENT) ? -1 : -3;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -3;
    }
    if (st.st_size > (off_t)API_RESP_BODY_CAP) {
        close(fd);
        return -2;
    }
    size_t sz = (size_t)st.st_size;
    char* buf = NULL;
    if (sz > 0) {
        buf = (char*)malloc(sz);
        if (!buf) { close(fd); return -3; }
        size_t off = 0;
        while (off < sz) {
            ssize_t r = read(fd, buf + off, sz - off);
            if (r < 0) {
                if (errno == EINTR) continue;
                free(buf); close(fd); return -3;
            }
            if (r == 0) break; /* truncated — treat as success at off bytes */
            off += (size_t)r;
        }
        sz = off;
    }
    close(fd);
    *out_buf = buf;
    *out_len = sz;
    return 0;
}

/* Write `body` of `body_len` bytes to <root>/<coll>/<id>.json.
 * `excl` selects POST semantics (fail with EEXIST if file exists);
 * otherwise PUT semantics (atomic create-or-replace via tempfile + rename).
 *
 * Returns 0 on success, EEXIST if excl && file exists, or another errno
 * on failure. Auto-creates the {coll} directory on demand.
 */
static int write_file(const char* coll, size_t coll_len,
                      const char* id,   size_t id_len,
                      const char* body, size_t body_len,
                      bool excl) {
    char dir[512];
    ssize_t dn = build_fs_path(dir, sizeof(dir), coll, coll_len, NULL, 0);
    if (dn < 0) return ENAMETOOLONG;
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) return errno;

    char fpath[768];
    ssize_t fn = build_fs_path(fpath, sizeof(fpath), coll, coll_len, id, id_len);
    if (fn < 0) return ENAMETOOLONG;

    if (excl) {
        int fd = open(fpath, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        if (fd < 0) return errno;  /* may be EEXIST */
        size_t off = 0;
        while (off < body_len) {
            ssize_t w = write(fd, body + off, body_len - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                int e = errno;
                close(fd);
                unlink(fpath);
                return e;
            }
            off += (size_t)w;
        }
        if (close(fd) != 0) { unlink(fpath); return errno; }
        return 0;
    }

    /* PUT: tempfile + rename for atomic replace */
    char tmp[800];
    /* tmp = <dir>/.tmp.<id>.<pid>.<rand> */
    uint8_t r4[4] = {0};
    if (getrandom(r4, sizeof(r4), 0) < 0) {
        /* Non-fatal: fall back to deterministic-but-unique-per-pid bytes
         * (we still have the pid in the tmp name). */
    }
    int tn = snprintf(tmp, sizeof(tmp), "%s/.tmp.%.*s.%d.%02x%02x%02x%02x",
                      dir, (int)id_len, id, (int)getpid(),
                      r4[0], r4[1], r4[2], r4[3]);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp)) return ENAMETOOLONG;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return errno;
    size_t off = 0;
    while (off < body_len) {
        ssize_t w = write(fd, body + off, body_len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close(fd);
            unlink(tmp);
            return e;
        }
        off += (size_t)w;
    }
    if (close(fd) != 0) { int e = errno; unlink(tmp); return e; }
    if (rename(tmp, fpath) != 0) { int e = errno; unlink(tmp); return e; }
    return 0;
}

/* ---------- dispatcher ---------- */

void api_dispatch(http_method_t method,
                  const char* path, size_t path_len,
                  const char* body, size_t body_len,
                  api_resp_t* resp) {
    memset(resp, 0, sizeof(*resp));
    if (!g_enabled) { resp_status_only(resp, 404, "Not Found"); return; }

    const char* coll = NULL; size_t coll_len = 0;
    const char* id   = NULL; size_t id_len   = 0;
    int parts = split_path(path, path_len, &coll, &coll_len, &id, &id_len);
    if (parts < 0 || !is_valid_name(coll, coll_len)) {
        resp_text_error(resp, 400, "Bad Request", "invalid path\n");
        return;
    }
    if (id_len > 0 && !is_valid_name(id, id_len)) {
        resp_text_error(resp, 400, "Bad Request", "invalid id\n");
        return;
    }

    char fpath[768];

    switch (method) {
    case M_GET:
    case M_HEAD: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing id\n");
            return;
        }
        if (build_fs_path(fpath, sizeof(fpath), coll, coll_len, id, id_len) < 0) {
            resp_text_error(resp, 400, "Bad Request", "path too long\n");
            return;
        }
        char* buf = NULL; size_t blen = 0;
        int rc = read_file_full(fpath, &buf, &blen);
        if (rc == -1) { resp_status_only(resp, 404, "Not Found"); return; }
        if (rc == -2) { resp_text_error(resp, 500, "Internal Server Error", "object too large\n"); return; }
        if (rc < 0)   { resp_text_error(resp, 500, "Internal Server Error", "read failed\n"); return; }
        resp_get_body(resp, buf, blen, method == M_HEAD);
        return;
    }

    case M_PUT: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing id\n");
            return;
        }
        if (body_len > API_REQ_BODY_CAP) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        int rc = write_file(coll, coll_len, id, id_len, body, body_len, false);
        if (rc != 0) {
            resp_text_error(resp, 500, "Internal Server Error", "write failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    case M_POST: {
        if (body_len > API_REQ_BODY_CAP) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        if (id_len == 0) {
            /* Auto-generate id; loop on the unlikely EEXIST. */
            char gen[33];
            for (int attempt = 0; attempt < 8; attempt++) {
                if (!gen_id(gen)) {
                    resp_text_error(resp, 500, "Internal Server Error", "id gen failed\n");
                    return;
                }
                int rc = write_file(coll, coll_len, gen, 32, body, body_len, true);
                if (rc == 0) { resp_created(resp, coll, coll_len, gen, 32); return; }
                if (rc != EEXIST) {
                    resp_text_error(resp, 500, "Internal Server Error", "write failed\n");
                    return;
                }
            }
            resp_text_error(resp, 500, "Internal Server Error", "id gen retries exhausted\n");
            return;
        }
        /* Explicit id: create-only */
        int rc = write_file(coll, coll_len, id, id_len, body, body_len, true);
        if (rc == EEXIST) { resp_status_only(resp, 409, "Conflict"); return; }
        if (rc != 0)      { resp_text_error(resp, 500, "Internal Server Error", "write failed\n"); return; }
        resp_created(resp, coll, coll_len, id, id_len);
        return;
    }

    case M_DELETE: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing id\n");
            return;
        }
        if (build_fs_path(fpath, sizeof(fpath), coll, coll_len, id, id_len) < 0) {
            resp_text_error(resp, 400, "Bad Request", "path too long\n");
            return;
        }
        if (unlink(fpath) != 0) {
            if (errno == ENOENT) { resp_status_only(resp, 404, "Not Found"); return; }
            resp_text_error(resp, 500, "Internal Server Error", "delete failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    case M_UNKNOWN:
    default:
        resp_status_only(resp, 405, "Method Not Allowed");
        return;
    }
}

void api_resp_release(api_resp_t* resp) {
    if (!resp) return;
    if (resp->body_owned && resp->body) {
        free(resp->body);
    }
    resp->body = NULL;
    resp->body_len = 0;
    resp->body_owned = false;
}
