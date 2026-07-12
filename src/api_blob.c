/* api_blob.c — content-addressed HTTPS blob store mounted into picoweb's
 * existing TLS-terminating API layer. See api_blob.h for the protocol. */

#include "api_blob.h"
#include "security_headers.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BLOB_SHARD_PREFIX_LEN 2U
#define BLOB_SHA256_DIGEST_BYTES 32U
#define BLOB_SHA256_HEX_BYTES (BLOB_SHA256_DIGEST_BYTES * 2U)

static char   g_blob_root[512]  = {0};
static size_t g_blob_root_len   = 0;
static int    g_blob_root_fd    = -1;
static char   g_blob_prefix[64] = {0};
static size_t g_blob_prefix_len = 0;
static bool   g_blob_enabled    = false;

bool api_blob_enabled(void) { return g_blob_enabled; }

static bool blob_valid_prefix(const char* prefix, size_t cap) {
    size_t pl = prefix ? strlen(prefix) : 0;
    if (pl < 2 || pl >= cap) {
        fprintf(stderr, "api_blob: invalid --blob-prefix (must be 2..%zu chars, start and end with '/')\n", cap - 1);
        return false;
    }
    if (prefix[0] != '/' || prefix[pl - 1] != '/') {
        fprintf(stderr, "api_blob: invalid --blob-prefix '%s' (must start and end with '/')\n", prefix);
        return false;
    }
    return true;
}

bool api_blob_init(const char* root_dir, const char* prefix) {
    if (g_blob_root_fd >= 0) {
        close(g_blob_root_fd);
        g_blob_root_fd = -1;
    }
    g_blob_enabled = false;
    if (!root_dir || !root_dir[0] || !prefix || !prefix[0]) return false;
    if (!blob_valid_prefix(prefix, sizeof(g_blob_prefix))) return false;

    size_t rl = strlen(root_dir);
    if (rl >= sizeof(g_blob_root) - 1) {
        fprintf(stderr, "api_blob: --blob-root path too long (%zu >= %zu)\n", rl, sizeof(g_blob_root));
        return false;
    }

    bool created_root = false;
    if (mkdir(root_dir, 0700) == 0) {
        created_root = true;
    } else if (errno != EEXIST) {
        fprintf(stderr, "api_blob: cannot create --blob-root '%s': %s\n", root_dir, strerror(errno));
        return false;
    }

    int root_fd = open(root_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (root_fd < 0) {
        fprintf(stderr, "api_blob: cannot open --blob-root '%s': %s\n", root_dir, strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(root_fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        close(root_fd);
        fprintf(stderr, "api_blob: --blob-root '%s' is not a directory\n", root_dir);
        return false;
    }
    if (created_root && fchmod(root_fd, 0700) != 0) {
        close(root_fd);
        fprintf(stderr, "api_blob: cannot set permissions on --blob-root '%s': %s\n", root_dir, strerror(errno));
        return false;
    }

    memcpy(g_blob_root, root_dir, rl);
    g_blob_root[rl] = '\0';
    while (rl > 1 && g_blob_root[rl - 1] == '/') { g_blob_root[--rl] = '\0'; }
    g_blob_root_len = rl;

    size_t pl = strlen(prefix);
    memcpy(g_blob_prefix, prefix, pl + 1);
    g_blob_prefix_len = pl;
    g_blob_root_fd = root_fd;
    g_blob_enabled = true;
    return true;
}

bool api_blob_path_matches(const char* path, size_t path_len) {
    if (!path || !g_blob_enabled) return false;
    return path_len >= g_blob_prefix_len && memcmp(path, g_blob_prefix, g_blob_prefix_len) == 0;
}

/* ---------------------------------------------------------------------
 * SHA-256 (FIPS 180-4), implemented in-tree so this module has no
 * third-party dependency for content addressing.
 * --------------------------------------------------------------------- */

struct blob_sha256_ctx {
    uint32_t state[8];
    uint64_t bit_len;
    uint8_t buffer[64];
    size_t buffer_len;
};

static const uint32_t BLOB_SHA256_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

static uint32_t blob_rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32U - n));
}

static void blob_sha256_init(struct blob_sha256_ctx *ctx) {
    static const uint32_t init_state[8] = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                             0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    memcpy(ctx->state, init_state, sizeof(init_state));
    ctx->bit_len = 0U;
    ctx->buffer_len = 0U;
}

static void blob_sha256_process_block(struct blob_sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16U; ++i) {
        w[i] = ((uint32_t)block[i * 4U] << 24U) | ((uint32_t)block[i * 4U + 1U] << 16U) |
               ((uint32_t)block[i * 4U + 2U] << 8U) | (uint32_t)block[i * 4U + 3U];
    }
    for (unsigned i = 16U; i < 64U; ++i) {
        const uint32_t s0 = blob_rotr32(w[i - 15U], 7U) ^ blob_rotr32(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
        const uint32_t s1 = blob_rotr32(w[i - 2U], 17U) ^ blob_rotr32(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
        w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (unsigned i = 0; i < 64U; ++i) {
        const uint32_t s1 = blob_rotr32(e, 6U) ^ blob_rotr32(e, 11U) ^ blob_rotr32(e, 25U);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + s1 + ch + BLOB_SHA256_K[i] + w[i];
        const uint32_t s0 = blob_rotr32(a, 2U) ^ blob_rotr32(a, 13U) ^ blob_rotr32(a, 22U);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void blob_sha256_update(struct blob_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bit_len += (uint64_t)len * 8U;
    size_t offset = 0;
    if (ctx->buffer_len > 0U) {
        const size_t take = (64U - ctx->buffer_len < len) ? 64U - ctx->buffer_len : len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        offset += take;
        if (ctx->buffer_len == 64U) {
            blob_sha256_process_block(ctx, ctx->buffer);
            ctx->buffer_len = 0U;
        }
    }
    while (offset + 64U <= len) {
        blob_sha256_process_block(ctx, data + offset);
        offset += 64U;
    }
    const size_t remaining = len - offset;
    if (remaining > 0U) {
        memcpy(ctx->buffer, data + offset, remaining);
        ctx->buffer_len = remaining;
    }
}

static void blob_sha256_final(struct blob_sha256_ctx *ctx, uint8_t out[BLOB_SHA256_DIGEST_BYTES]) {
    const uint64_t bit_len = ctx->bit_len;
    uint8_t pad = 0x80U;
    blob_sha256_update(ctx, &pad, 1U);
    pad = 0x00U;
    while (ctx->buffer_len != 56U) {
        blob_sha256_update(ctx, &pad, 1U);
    }
    uint8_t len_bytes[8];
    for (unsigned i = 0; i < 8U; ++i) {
        len_bytes[i] = (uint8_t)(bit_len >> ((7U - i) * 8U));
    }
    memcpy(ctx->buffer + ctx->buffer_len, len_bytes, sizeof(len_bytes));
    ctx->buffer_len += sizeof(len_bytes);
    blob_sha256_process_block(ctx, ctx->buffer);
    ctx->buffer_len = 0U;
    for (unsigned i = 0; i < 8U; ++i) {
        out[i * 4U]      = (uint8_t)(ctx->state[i] >> 24U);
        out[i * 4U + 1U] = (uint8_t)(ctx->state[i] >> 16U);
        out[i * 4U + 2U] = (uint8_t)(ctx->state[i] >> 8U);
        out[i * 4U + 3U] = (uint8_t)ctx->state[i];
    }
}

static void blob_sha256_digest(const uint8_t *data, size_t len, uint8_t out[BLOB_SHA256_DIGEST_BYTES]) {
    struct blob_sha256_ctx ctx;
    blob_sha256_init(&ctx);
    blob_sha256_update(&ctx, data, len);
    blob_sha256_final(&ctx, out);
}

static void blob_bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2U] = digits[bytes[i] >> 4U];
        out[i * 2U + 1U] = digits[bytes[i] & 0x0fU];
    }
    out[len * 2U] = '\0';
}

static bool blob_hex_is_valid(const char *hex, size_t hex_len) {
    if (hex_len != BLOB_SHA256_HEX_BYTES) return false;
    for (size_t i = 0; i < BLOB_SHA256_HEX_BYTES; ++i) {
        const char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

/* ---------------------------------------------------------------------
 * Storage: dirfd-anchored, sharded by the first two hex chars of the
 * hash. Path is always hash-derived, never client free text, so no
 * traversal check beyond hex validation is needed.
 * --------------------------------------------------------------------- */

static bool blob_shard_name(const char *hex, char *out, size_t out_cap) {
    if (out_cap < BLOB_SHARD_PREFIX_LEN + 1U) return false;
    memcpy(out, hex, BLOB_SHARD_PREFIX_LEN);
    out[BLOB_SHARD_PREFIX_LEN] = '\0';
    return true;
}

static int blob_open_shard_dir(const char *hex, bool create, int *out_fd) {
    char shard[BLOB_SHARD_PREFIX_LEN + 1U];
    if (!blob_shard_name(hex, shard, sizeof(shard))) return EINVAL;

    int fd = openat(g_blob_root_fd, shard, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT && create) {
        if (mkdirat(g_blob_root_fd, shard, 0700) != 0 && errno != EEXIST) {
            return errno;
        }
        fd = openat(g_blob_root_fd, shard, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    }
    if (fd < 0) return errno;
    *out_fd = fd;
    return 0;
}

/* Returns 0 on success, EEXIST if the blob already exists (harmless:
 * content-addressed data is idempotent so callers may treat this as
 * success too), or another errno on failure. */
static int blob_write(const char *hex, const char *body, size_t body_len) {
    int shard_fd = -1;
    int rc = blob_open_shard_dir(hex, true, &shard_fd);
    if (rc != 0) return rc;

    struct stat st;
    if (fstatat(shard_fd, hex, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        close(shard_fd);
        return 0; /* already stored; content-addressed data never changes */
    }

    char tmp_name[BLOB_SHA256_HEX_BYTES + 16U];
    snprintf(tmp_name, sizeof(tmp_name), ".%s.tmp%d", hex, (int)getpid());

    int fd = openat(shard_fd, tmp_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        int e = errno;
        close(shard_fd);
        return e;
    }
    size_t off = 0;
    bool write_ok = true;
    while (off < body_len) {
        ssize_t n = write(fd, body + off, body_len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            write_ok = false;
            break;
        }
        off += (size_t)n;
    }
    if (write_ok && fsync(fd) != 0) write_ok = false;
    close(fd);
    if (!write_ok) {
        int e = errno;
        unlinkat(shard_fd, tmp_name, 0);
        close(shard_fd);
        return e ? e : EIO;
    }
    if (renameat(shard_fd, tmp_name, shard_fd, hex) != 0) {
        int e = errno;
        unlinkat(shard_fd, tmp_name, 0);
        close(shard_fd);
        return e;
    }
    close(shard_fd);
    return 0;
}

/* Returns 0 on success (sets out_buf/out_len, caller frees), -1 ENOENT,
 * -2 too large, -3 other I/O/OOM. */
static int blob_read(const char *hex, size_t max_bytes, char **out_buf, size_t *out_len) {
    int shard_fd = -1;
    int rc = blob_open_shard_dir(hex, false, &shard_fd);
    if (rc == ENOENT) return -1;
    if (rc != 0) return -3;

    int fd = openat(shard_fd, hex, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(shard_fd);
    if (fd < 0) {
        return (errno == ENOENT) ? -1 : -3;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -3;
    }
    if ((size_t)st.st_size > max_bytes) {
        close(fd);
        return -2;
    }
    size_t sz = (size_t)st.st_size;
    char *buf = NULL;
    if (sz > 0) {
        buf = (char *)malloc(sz);
        if (!buf) { close(fd); return -3; }
        size_t off = 0;
        while (off < sz) {
            ssize_t n = read(fd, buf + off, sz - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                free(buf); close(fd); return -3;
            }
            if (n == 0) break;
            off += (size_t)n;
        }
        sz = off;
    }
    close(fd);
    *out_buf = buf;
    *out_len = sz;
    return 0;
}

/* Returns true if the blob existed and was removed. */
static bool blob_delete(const char *hex) {
    int shard_fd = -1;
    if (blob_open_shard_dir(hex, false, &shard_fd) != 0) return false;
    bool removed = unlinkat(shard_fd, hex, 0) == 0;
    close(shard_fd);
    return removed;
}

/* ---------------------------------------------------------------------
 * Response builders -- header format matches api.c's conventions
 * (security headers, no-store, explicit Content-Length) so blob
 * responses look consistent with the rest of the API surface.
 * --------------------------------------------------------------------- */

static void blob_resp_finish_head(api_resp_t *r, int n) {
    if (n > 0 && (size_t)n < sizeof(r->head) - 2) {
        memcpy(r->head + n, "\r\n", 2);
        r->head_len = (size_t)n + 2;
        return;
    }
    r->status = 500;
    static const char overflow[] =
        "HTTP/1.1 500 Internal Server Error\r\nServer: picoweb\r\nContent-Length: 0\r\n\r\n";
    memcpy(r->head, overflow, sizeof(overflow) - 1);
    r->head_len = sizeof(overflow) - 1;
}

static void blob_resp_status_only(api_resp_t *r, int status, const char *reason) {
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Content-Length: 0\r\n"
                     PICOWEB_SECURITY_HEADERS
                     "Cache-Control: no-store\r\n"
                     "Connection: close\r\n",
                     status, reason);
    blob_resp_finish_head(r, n);
}

static void blob_resp_text_error(api_resp_t *r, int status, const char *reason, const char *body) {
    size_t blen = body ? strlen(body) : 0;
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Content-Type: text/plain; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     PICOWEB_SECURITY_HEADERS
                     "Cache-Control: no-store\r\n"
                     "Connection: close\r\n",
                     status, reason, blen);
    blob_resp_finish_head(r, n);
    if (blen) {
        r->body = (char *)malloc(blen);
        if (r->body) {
            memcpy(r->body, body, blen);
            r->body_len = blen;
            r->body_owned = true;
        } else {
            r->head_len = 0;
            blob_resp_status_only(r, 500, "Internal Server Error");
        }
    }
}

static void blob_resp_get_body(api_resp_t *r, char *body, size_t blen, bool head_only) {
    r->status = 200;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 200 OK\r\n"
                     "Server: picoweb\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "Content-Length: %zu\r\n"
                     PICOWEB_SECURITY_HEADERS
                     "Cache-Control: no-store\r\n"
                     "Connection: close\r\n",
                     blen);
    blob_resp_finish_head(r, n);
    if (r->status != 200 || head_only) {
        free(body);
        return;
    }
    r->body = body;
    r->body_len = blen;
    r->body_owned = true;
}

static void blob_resp_created(api_resp_t *r, const char *hex) {
    r->status = 201;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 201 Created\r\n"
                     "Server: picoweb\r\n"
                     "Location: %s%s\r\n"
                     "Content-Type: text/plain; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     PICOWEB_SECURITY_HEADERS
                     "Cache-Control: no-store\r\n"
                     "Connection: close\r\n",
                     g_blob_prefix, hex, (size_t)BLOB_SHA256_HEX_BYTES);
    blob_resp_finish_head(r, n);
    r->body = (char *)malloc(BLOB_SHA256_HEX_BYTES);
    if (r->body) {
        memcpy(r->body, hex, BLOB_SHA256_HEX_BYTES);
        r->body_len = BLOB_SHA256_HEX_BYTES;
        r->body_owned = true;
    }
}

void api_blob_dispatch(http_method_t method,
                       const char *path, size_t path_len,
                       const char *body, size_t body_len,
                       api_resp_t *resp) {
    const char *rest = path + g_blob_prefix_len;
    const size_t rest_len = path_len - g_blob_prefix_len;

    switch (method) {
    case M_POST: {
        if (rest_len != 0) {
            blob_resp_text_error(resp, 400, "Bad Request", "POST does not take a path segment\n");
            return;
        }
        uint8_t digest[BLOB_SHA256_DIGEST_BYTES];
        blob_sha256_digest((const uint8_t *)body, body_len, digest);
        char hex[BLOB_SHA256_HEX_BYTES + 1U];
        blob_bytes_to_hex(digest, sizeof(digest), hex);

        int rc = blob_write(hex, body, body_len);
        if (rc != 0) {
            blob_resp_text_error(resp, 500, "Internal Server Error", "blob write failed\n");
            return;
        }
        blob_resp_created(resp, hex);
        return;
    }

    case M_GET:
    case M_HEAD: {
        if (rest_len == 0 || !blob_hex_is_valid(rest, rest_len)) {
            blob_resp_text_error(resp, 400, "Bad Request", "missing or invalid hash\n");
            return;
        }
        char hex[BLOB_SHA256_HEX_BYTES + 1U];
        memcpy(hex, rest, BLOB_SHA256_HEX_BYTES);
        hex[BLOB_SHA256_HEX_BYTES] = '\0';

        char *buf = NULL;
        size_t blen = 0;
        int rc = blob_read(hex, API_RESP_BODY_CAP, &buf, &blen);
        if (rc == -1) { blob_resp_status_only(resp, 404, "Not Found"); return; }
        if (rc == -2) { blob_resp_text_error(resp, 500, "Internal Server Error", "object too large\n"); return; }
        if (rc < 0)   { blob_resp_text_error(resp, 500, "Internal Server Error", "read failed\n"); return; }
        blob_resp_get_body(resp, buf, blen, method == M_HEAD);
        return;
    }

    case M_DELETE: {
        if (rest_len == 0 || !blob_hex_is_valid(rest, rest_len)) {
            blob_resp_text_error(resp, 400, "Bad Request", "missing or invalid hash\n");
            return;
        }
        char hex[BLOB_SHA256_HEX_BYTES + 1U];
        memcpy(hex, rest, BLOB_SHA256_HEX_BYTES);
        hex[BLOB_SHA256_HEX_BYTES] = '\0';

        if (!blob_delete(hex)) {
            blob_resp_status_only(resp, 404, "Not Found");
            return;
        }
        blob_resp_status_only(resp, 204, "No Content");
        return;
    }

    case M_OPTIONS:
        blob_resp_status_only(resp, 204, "No Content");
        return;

    case M_UNKNOWN:
    default:
        blob_resp_status_only(resp, 405, "Method Not Allowed");
        return;
    }
}

