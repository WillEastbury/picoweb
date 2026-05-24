#include "jumptable.h"
#include "brotli.h"
#include "compress.h"
#include "metrics.h"
#include "mime.h"
#include "preload.h"
#include "simd.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define KEY_SEP_BYTE '|'
#define DEFAULT_HOST "_default"
#define DEFAULT_HOST_LEN 8

/* Read PICOWEB_NO_GZIP once. When set (=1/true/yes), gzip variants are
 * not built; only Brotli + identity remain. Every browser shipped
 * since ~2017 supports `br`, so on a modern audience this is a free
 * 10-15% of arena RAM. */
static bool no_gzip_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* v = getenv("PICOWEB_NO_GZIP");
        cached = (v && (v[0] == '1' || v[0] == 't' || v[0] == 'T'
                         || v[0] == 'y' || v[0] == 'Y')) ? 1 : 0;
    }
    return cached != 0;
}

static bool brotli_primary_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* v = getenv("PICOWEB_BROTLI_PRIMARY");
        cached = (v && (v[0] == '1' || v[0] == 't' || v[0] == 'T'
                         || v[0] == 'y' || v[0] == 'Y')) ? 1 : 0;
    }
    return cached != 0;
}

/* ============================================================== */
/* Flat hash table (single tier).                                 */
/* The key is logically (host || '|' || path). Hash is computed   */
/* incrementally so we never concatenate at request time.         */
/* ============================================================== */

static uint64_t key_hash(const char* host, size_t host_len,
                         const char* path, size_t path_len) {
    uint64_t h = metal_fnv1a_init();
    /* host is already lowercased on both sides (build + parser) */
    h = metal_fnv1a_step(h, host, host_len);
    uint8_t sep = KEY_SEP_BYTE;
    h = metal_fnv1a_step(h, &sep, 1);
    h = metal_fnv1a_step(h, path, path_len);
    return h;
}

static void flat_init(jumptable_t* jt, size_t expected_entries) {
    size_t need = expected_entries * 2 + 1;
    size_t cap = metal_next_pow2(need);
    if (cap < 16) cap = 16;
    jt->slots = (flat_slot_t*)arena_alloc(&jt->arena,
                                          cap * sizeof(flat_slot_t), 64);
    memset(jt->slots, 0, cap * sizeof(flat_slot_t));
    jt->cap = cap;
    jt->mask = cap - 1;
    jt->size = 0;
}

static void flat_insert(jumptable_t* jt,
                        const char* host, size_t host_len,
                        const char* path, size_t path_len,
                        resource_t* value) {
    if (host_len > 0xffff || path_len > 0xffff) {
        metal_die("flat_insert: lens overflow host=%zu path=%zu",
                  host_len, path_len);
    }
    uint64_t h = key_hash(host, host_len, path, path_len);
    uint32_t lens = ((uint32_t)host_len << 16) | (uint32_t)path_len;
    size_t i = (size_t)(h & jt->mask);
    for (size_t probes = 0; probes < jt->cap; probes++) {
        flat_slot_t* s = &jt->slots[i];
        if (s->value == NULL) {
            s->hash  = h;
            s->value = value;
            s->host  = host;
            s->path  = path;
            s->lens  = lens;
            jt->size++;
            /* Defensive: ensure we always keep at least 1 empty slot
             * so the unbounded lookup loop is guaranteed to terminate. */
            if (jt->size + 1 >= jt->cap) {
                metal_die("flat table near full (size=%zu cap=%zu)",
                          jt->size, jt->cap);
            }
            return;
        }
        if (s->hash == h && s->lens == lens
            && memcmp(s->host, host, host_len) == 0
            && memcmp(s->path, path, path_len) == 0) {
            /* duplicate — keep first */
            return;
        }
        i = (i + 1) & jt->mask;
    }
    metal_die("flat table full while inserting (host=%.*s path=%.*s)",
              (int)host_len, host, (int)path_len, path);
}

static __attribute__((hot)) const resource_t* flat_lookup(
        const jumptable_t* jt,
        const char* host, size_t host_len,
        const char* path, size_t path_len) {
    if (jt->cap == 0) return NULL;
    /* Note: host_len/path_len are bounded by the parser well below
     * 0xffff (host_len <= 255 by HTTP, path_len <= 2048 by MAX_URI_LEN).
     * No runtime check needed on the hot path. */
    uint64_t h = key_hash(host, host_len, path, path_len);
    uint32_t lens = ((uint32_t)host_len << 16) | (uint32_t)path_len;
    size_t mask = jt->mask;
    size_t i = (size_t)(h & mask);
    const flat_slot_t* slots = jt->slots;
    /* Unbounded loop — flat_insert guarantees at least one empty slot. */
    for (;;) {
        const flat_slot_t* s = &slots[i];
        __builtin_prefetch(&slots[(i + 1) & mask]);
        resource_t* v = s->value;
        if (__builtin_expect(v == NULL, 0)) return NULL;
        if (__builtin_expect(s->hash == h, 1)) {
            if (s->lens == lens
                && metal_eq_n(s->host, host, host_len)
                && metal_eq_n(s->path, path, path_len)) {
                return v;
            }
        }
        i = (i + 1) & mask;
    }
}

/* ============================================================== */
/* Build-time scratch (malloc-backed, freed after build).         */
/* ============================================================== */

typedef struct build_file {
    struct build_file* next;
    char*  name;       size_t name_len;
    char*  fs_path;
    off_t  size;
} build_file_t;

typedef struct build_dir {
    struct build_dir* next;
    char*  path;       size_t path_len;   /* URL dir, e.g. "/" or "/css" */
    build_file_t* files;
    size_t n_files;
} build_dir_t;

typedef struct build_host {
    struct build_host* next;
    char*  name;       size_t name_len;   /* lowercased */
    build_dir_t* dirs;
    size_t total_files;
    size_t total_body_bytes;
    size_t n_index_aliases; /* extra entries we'll insert for index.html */
    /* Optional chrome (header/footer) wrap for HTML pages of this host.
     * Source files: wwwroot/<host>/_chrome/header.html and footer.html.
     * Either may be missing/empty independently. */
    char*  chrome_hdr;  size_t chrome_hdr_len;
    char*  chrome_ftr;  size_t chrome_ftr_len;
    /* True when wwwroot/<host>/_pages/ exists. Files there are mapped
     * into URL space with the _pages prefix stripped, and take priority
     * over collisions with regular content. */
    bool   has_pages;
} build_host_t;

static void build_free(build_host_t* hosts) {
    while (hosts) {
        build_host_t* nh = hosts->next;
        for (build_dir_t* d = hosts->dirs; d; ) {
            build_dir_t* nd = d->next;
            for (build_file_t* f = d->files; f; ) {
                build_file_t* nf = f->next;
                free(f->name); free(f->fs_path); free(f);
                f = nf;
            }
            free(d->path); free(d);
            d = nd;
        }
        free(hosts->name);
        free(hosts->chrome_hdr);
        free(hosts->chrome_ftr);
        free(hosts);
        hosts = nh;
    }
}

static build_dir_t* build_find_or_add_dir(build_host_t* host,
                                          const char* dir_path,
                                          size_t dir_path_len) {
    for (build_dir_t* d = host->dirs; d; d = d->next) {
        if (d->path_len == dir_path_len &&
            memcmp(d->path, dir_path, dir_path_len) == 0) return d;
    }
    build_dir_t* d = (build_dir_t*)calloc(1, sizeof(*d));
    if (!d) metal_die("oom build_dir");
    d->path = (char*)malloc(dir_path_len + 1);
    if (!d->path) metal_die("oom build_dir.path");
    memcpy(d->path, dir_path, dir_path_len);
    d->path[dir_path_len] = '\0';
    d->path_len = dir_path_len;
    d->next = host->dirs;
    host->dirs = d;
    return d;
}

static void build_add_file(build_host_t* host, const char* dir_path,
                           size_t dir_path_len, const char* name,
                           const char* fs_path, off_t size) {
    build_dir_t* d = build_find_or_add_dir(host, dir_path, dir_path_len);
    build_file_t* f = (build_file_t*)calloc(1, sizeof(*f));
    if (!f) metal_die("oom build_file");
    size_t nlen = strlen(name);
    f->name = (char*)malloc(nlen + 1);
    f->fs_path = strdup(fs_path);
    if (!f->name || !f->fs_path) metal_die("oom build_file strs");
    memcpy(f->name, name, nlen + 1);
    f->name_len = nlen;
    f->size = size;
    f->next = d->files;
    d->files = f;
    d->n_files++;
    host->total_files++;
    host->total_body_bytes += (size_t)size;
    if (nlen == 10 && memcmp(name, "index.html", 10) == 0) {
        /* dir==/ contributes 1 alias ("/"); other dirs contribute 2
         * ("/foo", "/foo/") on top of the canonical "/foo/index.html". */
        host->n_index_aliases += (dir_path_len == 1) ? 1 : 2;
    }
}

static void walk_host_dir(build_host_t* host, const char* fs_dir,
                          const char* url_dir, size_t url_dir_len) {
    DIR* d = opendir(fs_dir);
    if (!d) {
        metal_log("warn: opendir %s: %s", fs_dir, strerror(errno));
        return;
    }
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char child_fs[4096];
        int n = snprintf(child_fs, sizeof(child_fs), "%s/%s", fs_dir, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child_fs)) {
            metal_log("warn: path too long under %s", fs_dir);
            continue;
        }
        struct stat st;
        if (lstat(child_fs, &st) != 0) {
            metal_log("warn: lstat %s: %s", child_fs, strerror(errno));
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            build_add_file(host, url_dir, url_dir_len, ent->d_name, child_fs, st.st_size);
        } else if (S_ISDIR(st.st_mode)) {
            /* Hidden-from-URL convention: any directory starting with
             * '_' is reserved for internal use (e.g. _chrome/) and is
             * not enumerated as servable content. */
            if (ent->d_name[0] == '_') continue;
            char child_url[4096];
            int m;
            if (url_dir_len == 1 && url_dir[0] == '/') {
                m = snprintf(child_url, sizeof(child_url), "/%s", ent->d_name);
            } else {
                m = snprintf(child_url, sizeof(child_url), "%.*s/%s",
                             (int)url_dir_len, url_dir, ent->d_name);
            }
            if (m <= 0 || (size_t)m >= sizeof(child_url)) {
                metal_log("warn: url path too long under %s", url_dir);
                continue;
            }
            walk_host_dir(host, child_fs, child_url, (size_t)m);
        }
    }
    closedir(d);
}

/* Read up to max_size bytes of a file at fs_path into a freshly malloc'd
 * buffer. Returns NULL if the file doesn't exist or is empty/unreadable.
 * Returned buffer is owned by caller (must free()). Used only at build
 * time (chrome loader); not on the hot path. */
static char* slurp_to_malloc(const char* fs_path, size_t max_size, size_t* out_len) {
    int fd = open(fs_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0
        || (size_t)st.st_size > max_size) {
        close(fd);
        return NULL;
    }
    size_t sz = (size_t)st.st_size;
    char* buf = (char*)malloc(sz);
    if (!buf) { close(fd); return NULL; }
    size_t got = 0;
    while (got < sz) {
        ssize_t r = read(fd, buf + got, sz - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd); return NULL;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got == 0) { free(buf); return NULL; }
    *out_len = got;
    return buf;
}

/* Look for wwwroot/<host>/_chrome/header.html and footer.html.
 * Each is independently optional. Loads bytes into build_host_t for
 * later copy into the arena. */
#define CHROME_MAX_BYTES (1u * 1024u * 1024u)  /* 1 MiB cap per fragment */

static void load_chrome(build_host_t* host, const char* host_fs_dir) {
    char p[4096];
    int n = snprintf(p, sizeof(p), "%s/_chrome/header.html", host_fs_dir);
    if (n > 0 && (size_t)n < sizeof(p)) {
        host->chrome_hdr = slurp_to_malloc(p, CHROME_MAX_BYTES, &host->chrome_hdr_len);
    }
    n = snprintf(p, sizeof(p), "%s/_chrome/footer.html", host_fs_dir);
    if (n > 0 && (size_t)n < sizeof(p)) {
        host->chrome_ftr = slurp_to_malloc(p, CHROME_MAX_BYTES, &host->chrome_ftr_len);
    }
}

static build_host_t* build_scan(const char* wwwroot) {
    DIR* d = opendir(wwwroot);
    if (!d) {
        metal_log("error: opendir(wwwroot=%s): %s", wwwroot, strerror(errno));
        return NULL;
    }
    build_host_t* hosts = NULL;
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char child_fs[4096];
        int n = snprintf(child_fs, sizeof(child_fs), "%s/%s", wwwroot, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child_fs)) continue;
        struct stat st;
        if (lstat(child_fs, &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;

        size_t nlen = strlen(ent->d_name);
        if (nlen == 0 || nlen > 253) {
            metal_log("warn: skipping host with invalid name length: %s", ent->d_name);
            continue;
        }
        build_host_t* h = (build_host_t*)calloc(1, sizeof(*h));
        if (!h) metal_die("oom build_host");
        h->name = (char*)malloc(nlen + 1);
        if (!h->name) metal_die("oom build_host.name");
        memcpy(h->name, ent->d_name, nlen + 1);
        metal_lower_inplace(h->name, nlen);
        h->name_len = nlen;
        h->next = hosts;
        hosts = h;

        walk_host_dir(h, child_fs, "/", 1);
        load_chrome(h, child_fs);

        /* If <host>/_pages/ exists, walk it as a "virtual root": its
         * files map into URL space with the _pages prefix stripped.
         * We walk it AFTER the normal pass so that build_add_file's
         * LIFO insertion places these files at the head of each
         * affected dir's file list — meaning the build loop (which
         * iterates head-first) inserts them first into the flat
         * table, and flat_insert's "keep first on duplicate" rule
         * naturally lets the _pages version win. */
        char pages_fs[4096];
        int pn = snprintf(pages_fs, sizeof(pages_fs), "%s/_pages", child_fs);
        if (pn > 0 && (size_t)pn < sizeof(pages_fs)) {
            struct stat pst;
            if (lstat(pages_fs, &pst) == 0 && S_ISDIR(pst.st_mode)) {
                h->has_pages = true;
                walk_host_dir(h, pages_fs, "/", 1);
                metal_log("  host '%s': _pages/ enabled (chromed virtual root)",
                          h->name);
            }
        }
    }
    closedir(d);
    return hosts;
}

/* ============================================================== */
/* Response head construction.                                    */
/* ============================================================== */

static char g_date_buf[64];
static size_t g_date_len;

static void format_date_now(void) {
    time_t t = time(NULL);
    struct tm gm;
    gmtime_r(&t, &gm);
    g_date_len = strftime(g_date_buf, sizeof(g_date_buf),
                          "%a, %d %b %Y %H:%M:%S GMT", &gm);
}

static const char* build_head(arena_t* arena,
                              const char* status_line,
                              const char* mime_type,
                              size_t body_len,
                              const char* extra_header,
                              size_t* out_len) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
        "%s\r\n"
        "Server: picoweb\r\n"
        "Date: %.*s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "%s",
        status_line,
        (int)g_date_len, g_date_buf,
        mime_type,
        body_len,
        extra_header ? extra_header : "");
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        metal_die("response head too long for status %s", status_line);
    }
    *out_len = (size_t)n;
    /* 64-byte align so head reads land on a fresh cache line. */
    char* dst = (char*)arena_alloc(arena, (size_t)n, 64);
    memcpy(dst, buf, (size_t)n);
    return (const char*)dst;
}

/* Build a 304 Not Modified response head (no Content-Type/Content-Length).
 * Includes ETag and any cache/vary metadata from the original response.
 * Does NOT include Connection header or final blank line — caller
 * appends a shared connection-tail segment at send time. */
static const char* build_304_head(arena_t* arena,
                                  const char* etag,
                                  const char* cache_vary_header,
                                  size_t* out_len) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "HTTP/1.1 304 Not Modified\r\n"
        "Server: picoweb\r\n"
        "Date: %.*s\r\n"
        "ETag: %s\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "%s",
        (int)g_date_len, g_date_buf,
        etag,
        cache_vary_header ? cache_vary_header : "");
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        metal_die("304 head too long");
    }
    *out_len = (size_t)n;
    char* dst = (char*)arena_alloc(arena, (size_t)n, 64);
    memcpy(dst, buf, (size_t)n);
    return (const char*)dst;
}

static resource_t* build_resource(arena_t* arena,
                                  const char* status_line,
                                  const char* mime_type,
                                  const char* body_in_arena, size_t body_len,
                                  const char* extra_header) {
    resource_t* r = (resource_t*)arena_alloc(arena, sizeof(*r), 64);
    r->body = body_in_arena;
    r->body_len = body_len;
    r->chrome = NULL;
    r->compressed = NULL;
    r->brotli = NULL;
    r->brotli_primary = false;
    r->identity_len = body_len;
    r->head = build_head(arena, status_line, mime_type, body_len,
                         extra_header, &r->head_len);
    return r;
}

/* Build a resource with chrome wrap. The wire payload is
 * (chrome.hdr || body || chrome.ftr) so Content-Length must include
 * all three. The hot path then sendmsg's an iovec of head + hdr +
 * body + ftr — pointers only, no copies. */
static resource_t* build_resource_chromed(arena_t* arena,
                                          const char* status_line,
                                          const char* mime_type,
                                          const char* body_in_arena, size_t body_len,
                                          const chrome_t* chrome,
                                          const char* extra_header) {
    size_t total_payload = body_len
                         + (chrome ? chrome->hdr_len : 0)
                         + (chrome ? chrome->ftr_len : 0);
    resource_t* r = (resource_t*)arena_alloc(arena, sizeof(*r), 64);
    r->body = body_in_arena;
    r->body_len = body_len;
    r->chrome = chrome;
    r->compressed = NULL;
    r->brotli = NULL;
    r->brotli_primary = false;
    r->identity_len = total_payload;
    r->head = build_head(arena, status_line, mime_type, total_payload,
                         extra_header, &r->head_len);
    return r;
}

static resource_t* build_resource_brotli_primary(arena_t* arena,
                                                 const char* status_line,
                                                 const char* mime_type,
                                                 size_t identity_len,
                                                 const char* extra_header) {
    resource_t* r = (resource_t*)arena_alloc(arena, sizeof(*r), 64);
    r->body = NULL;
    r->body_len = 0;
    r->chrome = NULL;
    r->compressed = NULL;
    r->brotli = NULL;
    r->brotli_primary = true;
    r->identity_len = identity_len;
    r->head = build_head(arena, status_line, mime_type, identity_len,
                         extra_header, &r->head_len);
    return r;
}

/* Forward declaration for compute_etag (defined later with wire builders). */
static void compute_etag(char* out, size_t outsz,
                         const void* body, size_t body_len);

/* Build a precomputed compressed variant of `r`. Compresses the FULL
 * wire payload (chrome.hdr || body || chrome.ftr) if chromed, else
 * just body. Attaches via r->compressed if and only if the result is
 * strictly smaller than the uncompressed payload (otherwise we keep
 * r->compressed = NULL and clients silently fall back to identity).
 *
 * Headers carry an extra "Content-Encoding: picoweb-compress\r\n"
 * line and a Content-Length matching the compressed byte count.
 *
 * Uses a malloc'd scratch buffer for the input and bound; both are
 * freed before returning. The compressed bytes themselves are copied
 * into the immutable arena. */
static void attach_compressed_variant(arena_t* arena,
                                      resource_t* r,
                                      const char* status_line,
                                      const char* mime_type) {
    if (!r || !r->body_len) return;

    /* Step 1: assemble the raw payload (chrome+body if chromed). */
    size_t hdr_len = r->chrome ? r->chrome->hdr_len : 0;
    size_t ftr_len = r->chrome ? r->chrome->ftr_len : 0;
    size_t raw_len = hdr_len + r->body_len + ftr_len;
    if (raw_len == 0 || raw_len < hdr_len) return; /* overflow guard */

    uint8_t* raw = (uint8_t*)malloc(raw_len);
    if (!raw) return;
    size_t off = 0;
    if (hdr_len) { memcpy(raw + off, r->chrome->hdr, hdr_len); off += hdr_len; }
    memcpy(raw + off, r->body, r->body_len);                   off += r->body_len;
    if (ftr_len) { memcpy(raw + off, r->chrome->ftr, ftr_len); off += ftr_len; }

    /* Step 2: compress into a worst-case scratch. */
    size_t bound = metal_compress_bound(raw_len);
    uint8_t* tmp = (uint8_t*)malloc(bound);
    if (!tmp) { free(raw); return; }

    int got = metal_compress(raw, raw_len, tmp, bound);
    free(raw);
    if (got <= 0 || (size_t)got >= raw_len) {
        /* No win — drop the variant. */
        free(tmp);
        return;
    }

    /* Step 3: copy compressed bytes into the arena. */
    void* body_pc = arena_dup(arena, tmp, (size_t)got);
    free(tmp);
    if (!body_pc) return;

    /* Step 4: build the variant heads with ETag. */
    resource_compress_t* rc = (resource_compress_t*)
        arena_alloc(arena, sizeof(*rc), 64);
    rc->body = (const char*)body_pc;
    rc->body_len = (size_t)got;
    rc->decoded_len = raw_len;
    memset(rc->etag, 0, sizeof(rc->etag));

    /* Compute ETag from compressed bytes. */
    compute_etag(rc->etag, sizeof(rc->etag), body_pc, (size_t)got);

    char extra_buf[256];
    snprintf(extra_buf, sizeof(extra_buf),
             "Content-Encoding: picoweb-compress\r\n"
             "Vary: Accept-Encoding\r\n"
             "ETag: %s\r\n", rc->etag);

    rc->head = build_head(arena, status_line, mime_type, (size_t)got,
                          extra_buf, &rc->head_len);
    r->compressed = rc;
}

/* Build a Brotli-compressed variant of a resource. Same pattern as
 * attach_compressed_variant but uses our micro-brotli encoder. */
static bool attach_brotli_payload(arena_t* arena, resource_t* r,
                                  const void* raw_payload, size_t raw_len,
                                  const char* status_line,
                                  const char* mime_type,
                                  const char* cache_hdr) {
    if (!r || !raw_payload || !raw_len) return false;
    /* Compress */
    size_t bound = brotli_bound(raw_len);
    uint8_t* tmp = (uint8_t*)malloc(bound);
    if (!tmp) return false;

    int got = brotli_encode((const uint8_t*)raw_payload, raw_len, tmp, bound);
    if (got <= 0 || (size_t)got >= raw_len) {
        free(tmp);
        return false;
    }

    /* Copy into arena */
    void* body_br = arena_dup(arena, tmp, (size_t)got);
    free(tmp);
    if (!body_br) return false;

    /* Build variant headers with ETag */
    resource_compress_t* rc = (resource_compress_t*)
        arena_alloc(arena, sizeof(*rc), 64);
    rc->body = (const char*)body_br;
    rc->body_len = (size_t)got;
    rc->decoded_len = raw_len;
    memset(rc->etag, 0, sizeof(rc->etag));

    compute_etag(rc->etag, sizeof(rc->etag), body_br, (size_t)got);

    char extra[384];
    snprintf(extra, sizeof(extra),
             "Content-Encoding: br\r\n"
             "Vary: Accept-Encoding\r\n"
             "ETag: %s\r\n"
             "%s", rc->etag, cache_hdr ? cache_hdr : "");

    rc->head = build_head(arena, status_line, mime_type, (size_t)got,
                          extra, &rc->head_len);
    r->brotli = rc;
    return true;
}

static void attach_brotli_variant(arena_t* arena, resource_t* r,
                                  const char* status_line,
                                  const char* mime_type,
                                  const char* cache_hdr) {
    if (!r || !r->body_len) return;

    /* Assemble raw payload (chrome+body if chromed) */
    size_t hdr_len = r->chrome ? r->chrome->hdr_len : 0;
    size_t ftr_len = r->chrome ? r->chrome->ftr_len : 0;
    size_t raw_len = hdr_len + r->body_len + ftr_len;
    if (raw_len == 0 || raw_len < hdr_len) return; /* overflow guard */

    uint8_t* raw = (uint8_t*)malloc(raw_len);
    if (!raw) return;
    size_t off = 0;
    if (hdr_len) { memcpy(raw + off, r->chrome->hdr, hdr_len); off += hdr_len; }
    memcpy(raw + off, r->body, r->body_len); off += r->body_len;
    if (ftr_len) { memcpy(raw + off, r->chrome->ftr, ftr_len); }

    (void)attach_brotli_payload(arena, r, raw, raw_len,
                                status_line, mime_type, cache_hdr);
    free(raw);
}

static const char kBody400[] = "<!doctype html><title>400</title><h1>400 Bad Request</h1>";
static const char kBody404[] = "<!doctype html><title>404</title><h1>404 Not Found</h1>";
static const char kBody405[] = "<!doctype html><title>405</title><h1>405 Method Not Allowed</h1>";
static const char kBody409[] = "<!doctype html><title>409</title><h1>409 Conflict</h1><p>Unknown or missing Host</p>";
static const char kBody413[] = "<!doctype html><title>413</title><h1>413 Payload Too Large</h1>";
static const char kBody414[] = "<!doctype html><title>414</title><h1>414 URI Too Long</h1>";
static const char kBody500[] = "<!doctype html><title>500</title><h1>500 Internal Server Error</h1>";
static const char kBody505[] = "<!doctype html><title>505</title><h1>505 HTTP Version Not Supported</h1>";

/* Forward declarations for 304 buffer builders. */
static void build_304_resource(arena_t* arena, resource_t* r, const char* cache_vary_header);
static void build_304_variant(arena_t* arena, resource_compress_t* rc, const char* cache_vary_header);

__attribute__((cold))
static void build_canned_errors(jumptable_t* jt) {
    arena_t* a = &jt->arena;
    static const char kNoCache[] = "Cache-Control: no-cache\r\n";
    const char* b400 = (const char*)arena_dup(a, kBody400, sizeof(kBody400) - 1);
    const char* b404 = (const char*)arena_dup(a, kBody404, sizeof(kBody404) - 1);
    const char* b405 = (const char*)arena_dup(a, kBody405, sizeof(kBody405) - 1);
    const char* b409 = (const char*)arena_dup(a, kBody409, sizeof(kBody409) - 1);
    const char* b413 = (const char*)arena_dup(a, kBody413, sizeof(kBody413) - 1);
    const char* b414 = (const char*)arena_dup(a, kBody414, sizeof(kBody414) - 1);
    const char* b500 = (const char*)arena_dup(a, kBody500, sizeof(kBody500) - 1);
    const char* b505 = (const char*)arena_dup(a, kBody505, sizeof(kBody505) - 1);
    jt->err_400 = build_resource(a, "HTTP/1.1 400 Bad Request",
        "text/html; charset=utf-8", b400, sizeof(kBody400) - 1, kNoCache);
    jt->err_404 = build_resource(a, "HTTP/1.1 404 Not Found",
        "text/html; charset=utf-8", b404, sizeof(kBody404) - 1, kNoCache);
    jt->err_405 = build_resource(a, "HTTP/1.1 405 Method Not Allowed",
        "text/html; charset=utf-8", b405, sizeof(kBody405) - 1,
        "Allow: GET, HEAD\r\nCache-Control: no-cache\r\n");
    jt->err_409 = build_resource(a, "HTTP/1.1 409 Conflict",
        "text/html; charset=utf-8", b409, sizeof(kBody409) - 1, kNoCache);
    jt->err_413 = build_resource(a, "HTTP/1.1 413 Payload Too Large",
        "text/html; charset=utf-8", b413, sizeof(kBody413) - 1, kNoCache);
    jt->err_414 = build_resource(a, "HTTP/1.1 414 URI Too Long",
        "text/html; charset=utf-8", b414, sizeof(kBody414) - 1, kNoCache);
    jt->err_500 = build_resource(a, "HTTP/1.1 500 Internal Server Error",
        "text/html; charset=utf-8", b500, sizeof(kBody500) - 1, kNoCache);
    jt->err_505 = build_resource(a, "HTTP/1.1 505 HTTP Version Not Supported",
        "text/html; charset=utf-8", b505, sizeof(kBody505) - 1, kNoCache);
}

static const char* slurp(arena_t* arena, const char* path, off_t expected, size_t* out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        metal_log("warn: open %s: %s", path, strerror(errno));
        return NULL;
    }
    char* buf = (char*)arena_alloc(arena, (size_t)expected, 64);
    size_t got = 0;
    while (got < (size_t)expected) {
        ssize_t r = read(fd, buf + got, (size_t)expected - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            metal_log("warn: read %s: %s", path, strerror(errno));
            close(fd);
            return NULL;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    *out_len = got;
    return buf;
}

static char* slurp_heap(const char* path, off_t expected, size_t* out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        metal_log("warn: open %s: %s", path, strerror(errno));
        return NULL;
    }
    char* buf = (char*)malloc((size_t)expected ? (size_t)expected : 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    size_t got = 0;
    while (got < (size_t)expected) {
        ssize_t r = read(fd, buf + got, (size_t)expected - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            metal_log("warn: read %s: %s", path, strerror(errno));
            close(fd);
            free(buf);
            return NULL;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    *out_len = got;
    return buf;
}

/* Build a URL path from (dir, filename) into a small stack buffer. */
static int build_url(char* out, size_t outsz,
                     const char* dir, size_t dir_len,
                     const char* file, size_t file_len) {
    int n;
    if (dir_len == 1 && dir[0] == '/') {
        n = snprintf(out, outsz, "/%.*s", (int)file_len, file);
    } else {
        n = snprintf(out, outsz, "%.*s/%.*s",
                     (int)dir_len, dir, (int)file_len, file);
    }
    return n;
}

/* ============================================================== */
/* ETag computation.                                              */
/* Format: W/"<body_len_hex>-<fnv64_hex>" — weak validator.       */
/* Includes body length to reduce collision risk.                 */
/* ============================================================== */

static void compute_etag(char* out, size_t outsz,
                         const void* body, size_t body_len) {
    uint64_t h = metal_fnv1a(body, body_len);
    snprintf(out, outsz, "W/\"%zx-%016llx\"",
             body_len, (unsigned long long)h);
}

static void compute_etag_parts(char* out, size_t outsz,
                               const void* p1, size_t l1,
                               const void* p2, size_t l2,
                               const void* p3, size_t l3) {
    uint64_t h = metal_fnv1a_init();
    if (l1) h = metal_fnv1a_step(h, p1, l1);
    if (l2) h = metal_fnv1a_step(h, p2, l2);
    if (l3) h = metal_fnv1a_step(h, p3, l3);
    snprintf(out, outsz, "W/\"%zx-%016llx\"",
             l1 + l2 + l3, (unsigned long long)h);
}

/* ============================================================== */
/* 304 Not Modified wire buffers.                                 */
/* ============================================================== */

/* Build pre-rendered 304 Not Modified wire buffers for a resource.
 * Called after ETags are computed. cache_vary_header is the combined
 * Cache-Control + Vary lines (or NULL). */
static void build_304_resource(arena_t* arena, resource_t* r,
                               const char* cache_vary_header) {
    if (r->etag[0] == '\0') return;
    r->wire_304 = build_304_head(arena, r->etag, cache_vary_header,
                                 &r->wire_304_len);
}

static void build_304_variant(arena_t* arena, resource_compress_t* rc,
                              const char* cache_vary_header) {
    if (rc->etag[0] == '\0') return;
    rc->wire_304 = build_304_head(arena, rc->etag, cache_vary_header,
                                  &rc->wire_304_len);
}

/* ============================================================== */
/* Build phase                                                    */
/* ============================================================== */

__attribute__((cold))
bool jumptable_build(jumptable_t* jt, const char* wwwroot) {
    memset(jt, 0, sizeof(*jt));
    format_date_now();

    build_host_t* hosts = build_scan(wwwroot);
    if (!hosts) {
        metal_log("error: no hosts found under %s", wwwroot);
        return false;
    }

    /* Sizing */
    size_t total_files = 0, total_dirs = 0, total_hosts = 0,
           total_bytes = 0, total_aliases = 0, total_chrome_bytes = 0;
    for (build_host_t* h = hosts; h; h = h->next) {
        total_hosts++;
        total_files += h->total_files;
        total_aliases += h->n_index_aliases;
        for (build_dir_t* d = h->dirs; d; d = d->next) total_dirs++;
        total_bytes += h->total_body_bytes;
        total_chrome_bytes += h->chrome_hdr_len + h->chrome_ftr_len;
    }

    size_t total_entries = total_files + total_aliases;
    /* Plus 2 special endpoints (/health, /stats) per host. */
    size_t metric_entries = total_hosts * 2;
    total_entries += metric_entries;
    /* Slot count → flat table size. Load factor ~0.5 means cap = 2x.
     * Each slot is 40B; 4x oversize is still trivial for typical sites. */
    size_t slot_count = metal_next_pow2(total_entries * 2 + 1);
    if (slot_count < 16) slot_count = 16;

    /* Estimate arena: file bytes + ~768B per resource (head x2 + struct
     * + key strings) + slot table + per-host name + slack. Includes
     * metric_entries for the path-key strings ("/health", "/stats")
     * plus 2 extra resource_t's (one /health, one /stats — shared
     * across hosts), plus per-host chrome bytes (header + footer copied
     * into arena once per host) and a chrome_t struct per host.
     *
     * Pre-compressed variants: every text resource gets an extra
     * arena copy up to ~120% of its raw payload (worst case: stored
     * verbatim per block + 4-byte block headers) plus a
     * resource_compress_t struct + two variant heads. We budget for
     * this against EVERY body byte (cheap over-approximation; the
     * bound is tight on text and a no-op on binary). */
    /* Checked arena capacity — guard against size_t overflow on extreme
     * site trees.  Each addend is individually bounded by SIZE_MAX/16
     * so the running sum cannot wrap with fewer than 16 terms. */
    #define SAFE_CAP (SIZE_MAX / 16)
    if (total_bytes > SAFE_CAP || total_entries > SAFE_CAP / 1024 ||
        slot_count > SAFE_CAP / sizeof(flat_slot_t)) {
        metal_log("error: site tree too large for arena sizing");
        build_free(hosts);
        return false;
    }
    size_t arena_cap = total_bytes
                     + total_bytes * 6 / 5         /* compressed copies */
                     + total_bytes * 6 / 5         /* brotli copies */
                     + total_entries * 768
                     + total_entries * 512         /* resource_compress_t*2 + variant heads */
                     + slot_count * sizeof(flat_slot_t)
                     + total_hosts * 512
                     + 2 * 768                   /* /health + /stats heads */
                     + total_chrome_bytes
                     + total_hosts * 128         /* chrome_t per host (aligned 64) */
                     + 64 * 1024;
    #undef SAFE_CAP
    if (!arena_init(&jt->arena, arena_cap)) {
        metal_log("error: arena_init(%zu) failed", arena_cap);
        build_free(hosts);
        return false;
    }
    metal_log("picoweb: arena %zu B for %zu host(s) / %zu dir(s) / "
              "%zu file(s) (+%zu aliases) / %zu body B / %zu slots",
              arena_cap, total_hosts, total_dirs, total_files,
              total_aliases, total_bytes, slot_count);

    flat_init(jt, total_entries);

    /* For each host, copy host name into arena (lowercased), then for
     * each file: slurp body, build heads, insert canonical + aliases. */
    for (build_host_t* h = hosts; h; h = h->next) {
        const char* host_key = arena_strdup_n(&jt->arena, h->name, h->name_len, false);
        if (h->name_len == DEFAULT_HOST_LEN &&
            memcmp(h->name, DEFAULT_HOST, DEFAULT_HOST_LEN) == 0) {
            jt->has_default = true;
        }

        /* Register in known_hosts for virtual-host validation. */
        if (jt->known_host_count >= 128)
            metal_die("too many virtual hosts (max 128)");
        jt->known_hosts[jt->known_host_count].name = host_key;
        jt->known_hosts[jt->known_host_count].len = h->name_len;
        jt->known_host_count++;

        /* Materialize per-host chrome. Header and footer bytes are copied
         * into the (immutable) arena ONCE per host and shared by every
         * HTML resource for the host via a single chrome_t pointer. */
        const chrome_t* host_chrome = NULL;
        if (h->chrome_hdr_len > 0 || h->chrome_ftr_len > 0) {
            chrome_t* ch = (chrome_t*)arena_alloc(&jt->arena, sizeof(*ch), 64);
            ch->hdr_len = h->chrome_hdr_len;
            ch->ftr_len = h->chrome_ftr_len;
            ch->hdr = ch->hdr_len
                      ? (const char*)arena_dup(&jt->arena, h->chrome_hdr, ch->hdr_len)
                      : NULL;
            ch->ftr = ch->ftr_len
                      ? (const char*)arena_dup(&jt->arena, h->chrome_ftr, ch->ftr_len)
                      : NULL;
            host_chrome = ch;
            metal_log("  host '%s': chrome hdr=%zuB ftr=%zuB",
                      h->name, ch->hdr_len, ch->ftr_len);
        }

        for (build_dir_t* d = h->dirs; d; d = d->next) {
            for (build_file_t* f = d->files; f; f = f->next) {
                size_t got = 0;
                const char* mime = mime_lookup(f->name, f->name_len);
                bool is_html = (host_chrome != NULL)
                            && strncmp(mime, "text/html", 9) == 0;
                bool compressible = mime_is_compressible(mime);
                bool br_primary = compressible && brotli_primary_enabled();

                char* heap_body = NULL;
                const char* body = NULL;
                if (br_primary) {
                    heap_body = slurp_heap(f->fs_path, f->size, &got);
                    body = heap_body;
                } else {
                    body = slurp(&jt->arena, f->fs_path, f->size, &got);
                }
                if (!body) continue;

                /* Cache-Control policy:
                 * HTML pages: 1 hour (content may change)
                 * Other static assets: 1 day
                 * Compressible resources also get Vary for identity responses. */
                const char* extra_hdr;
                const char* cache_hdr;  /* just the Cache-Control line for variants */
                if (is_html) {
                    if (compressible)
                        extra_hdr = "Cache-Control: public, max-age=3600\r\n"
                                    "Vary: Accept-Encoding\r\n";
                    else
                        extra_hdr = "Cache-Control: public, max-age=3600\r\n";
                    cache_hdr = "Cache-Control: public, max-age=3600\r\n";
                } else if (compressible) {
                    extra_hdr = "Cache-Control: public, max-age=86400\r\n"
                                "Vary: Accept-Encoding\r\n";
                    cache_hdr = "Cache-Control: public, max-age=86400\r\n";
                } else {
                        extra_hdr = "Cache-Control: public, max-age=86400\r\n";
                    cache_hdr = "Cache-Control: public, max-age=86400\r\n";
                }

                size_t hdr_len = is_html && host_chrome ? host_chrome->hdr_len : 0;
                size_t ftr_len = is_html && host_chrome ? host_chrome->ftr_len : 0;
                size_t payload_len = hdr_len + got + ftr_len;
                if (payload_len < got || payload_len < hdr_len) {
                    free(heap_body);
                    continue;
                }
                uint8_t* payload_buf = NULL;
                const void* payload_ptr = body;
                if (hdr_len || ftr_len) {
                    payload_buf = (uint8_t*)malloc(payload_len ? payload_len : 1);
                    if (!payload_buf) {
                        free(heap_body);
                        continue;
                    }
                    size_t p = 0;
                    if (hdr_len) { memcpy(payload_buf + p, host_chrome->hdr, hdr_len); p += hdr_len; }
                    memcpy(payload_buf + p, body, got); p += got;
                    if (ftr_len) { memcpy(payload_buf + p, host_chrome->ftr, ftr_len); }
                    payload_ptr = payload_buf;
                }

                resource_t* r = br_primary
                    ? build_resource_brotli_primary(&jt->arena, "HTTP/1.1 200 OK",
                                                    mime, payload_len, extra_hdr)
                    : (is_html
                        ? build_resource_chromed(&jt->arena, "HTTP/1.1 200 OK",
                                                 mime, body, got, host_chrome, extra_hdr)
                        : build_resource(&jt->arena, "HTTP/1.1 200 OK",
                                         mime, body, got, extra_hdr));

                compute_etag(r->etag, sizeof(r->etag), payload_ptr, payload_len);

                /* Rebuild identity head with ETag included. The identity
                 * representation still advertises Vary so shared caches
                 * cannot mix it with the Brotli representation. */
                char etag_extra[384];
                snprintf(etag_extra, sizeof(etag_extra), "ETag: %s\r\n%s",
                         r->etag, extra_hdr);
                r->head = build_head(&jt->arena, "HTTP/1.1 200 OK",
                                     mime, payload_len,
                                     etag_extra, &r->head_len);

                /* Auto-derive HTTP 103 Early Hints `Link:` headers from
                 * subresources referenced in the HTML body (chrome+body+
                 * footer). Cached on the resource and emitted as a
                 * separate interim TLS record before the 200 response;
                 * also embedded in the 200 head for clients that don't
                 * speak 1xx. Per-resource so per-page assets are picked
                 * up; chrome-derived hints dominate via dedupe. */
                if (is_html && payload_ptr && payload_len) {
                    char tmp[PW_PRELOAD_HEADER_CAP];
                    size_t link_len = pw_preload_extract(
                        payload_ptr, payload_len,
                        host_key, h->name_len,
                        tmp, sizeof(tmp));
                    if (link_len > 0) {
                        char* link_buf = (char*)arena_dup(&jt->arena, tmp, link_len);
                        r->link_hdr = link_buf;
                        r->link_hdr_len = link_len;

                        /* Embed Link headers in the 200 head too,
                         * so clients that don't process 1xx still
                         * get the hint via the final response. */
                        size_t extra_room = strlen(extra_hdr) + link_len + 384;
                        char* combined = (char*)malloc(extra_room);
                        if (combined) {
                            int n = snprintf(combined, extra_room,
                                             "ETag: %s\r\n%s%.*s",
                                             r->etag, extra_hdr,
                                             (int)link_len, link_buf);
                            if (n > 0 && (size_t)n < extra_room) {
                                r->head = build_head(&jt->arena,
                                    "HTTP/1.1 200 OK", mime,
                                    payload_len, combined, &r->head_len);
                            }
                            free(combined);
                        }
                    }
                }

                /* Pre-compress text bodies for clients that opt in
                 * via Accept-Encoding. Variants are dropped silently if
                 * compression doesn't shrink the payload. Computed
                 * once at startup; never mutated on the hot path. */
                if (compressible) {
                    bool br_ok = false;
                    if (br_primary) {
                        br_ok = attach_brotli_payload(&jt->arena, r,
                                                      payload_ptr, payload_len,
                                                      "HTTP/1.1 200 OK",
                                                      mime, cache_hdr);
                        if (br_ok) {
                            r->chrome = NULL;
                            r->body = NULL;
                            r->body_len = 0;
                            r->identity_len = payload_len;
                            if (payload_len > jt->brotli_identity_scratch_len)
                                jt->brotli_identity_scratch_len = payload_len;
                        } else {
                            r->brotli_primary = false;
                            r->chrome = is_html ? host_chrome : NULL;
                            r->body = (const char*)arena_dup(&jt->arena, body, got);
                            r->body_len = got;
                        }
                    }
                    if (!br_primary && !no_gzip_enabled()) {
                        attach_compressed_variant(&jt->arena, r,
                                                  "HTTP/1.1 200 OK", mime);
                    }
                    if (!br_primary) {
                        attach_brotli_variant(&jt->arena, r,
                                              "HTTP/1.1 200 OK", mime, cache_hdr);
                    }
                }

                if (payload_buf) free(payload_buf);
                free(heap_body);

                /* Build 304 Not Modified wire buffers for conditional requests. */
                {
                    const char* cv_hdr = compressible
                        ? (is_html ? "Cache-Control: public, max-age=3600\r\nVary: Accept-Encoding\r\n"
                                   : "Cache-Control: public, max-age=86400\r\nVary: Accept-Encoding\r\n")
                        : (is_html ? "Cache-Control: public, max-age=3600\r\n"
                                   : "Cache-Control: public, max-age=86400\r\n");
                    build_304_resource(&jt->arena, r, cv_hdr);
                    if (r->compressed)
                        build_304_variant(&jt->arena, (resource_compress_t*)r->compressed,
                                          "Cache-Control: public, max-age=86400\r\nVary: Accept-Encoding\r\n");
                    if (r->brotli)
                        build_304_variant(&jt->arena, (resource_compress_t*)r->brotli,
                                          cv_hdr);
                }

                char url[8192];
                int ulen = build_url(url, sizeof(url), d->path, d->path_len,
                                     f->name, f->name_len);
                if (ulen <= 0 || (size_t)ulen >= sizeof(url)) {
                    metal_log("warn: url too long for %s", f->fs_path);
                    continue;
                }
                const char* path_key = arena_strdup_n(&jt->arena, url, (size_t)ulen, false);
                flat_insert(jt, host_key, h->name_len, path_key, (size_t)ulen, r);

                /* index.html aliases */
                if (f->name_len == 10 && memcmp(f->name, "index.html", 10) == 0) {
                    if (d->path_len == 1) {
                        /* root: also serve "/" */
                        const char* alias = arena_strdup_n(&jt->arena, "/", 1, false);
                        flat_insert(jt, host_key, h->name_len, alias, 1, r);
                    } else {
                        /* /foo: serve "/foo/" and "/foo" */
                        char buf[8192];
                        int blen = snprintf(buf, sizeof(buf), "%.*s/",
                                            (int)d->path_len, d->path);
                        const char* a1 = arena_strdup_n(&jt->arena, buf, (size_t)blen, false);
                        flat_insert(jt, host_key, h->name_len, a1, (size_t)blen, r);
                        const char* a2 = arena_strdup_n(&jt->arena, d->path, d->path_len, false);
                        flat_insert(jt, host_key, h->name_len, a2, d->path_len, r);
                    }
                }
            }
        }
        metal_log("  host '%s': %zu file(s)", h->name, h->total_files);
    }

    build_canned_errors(jt);

    /* Build /health and /stats resources (heads in arena, /stats body
     * in a separate writable mmap region owned by metrics module),
     * then insert under every host (so flat_lookup finds them with
     * no extra branches on the hot path). */
    metrics_build_resources(&jt->arena, g_date_buf, g_date_len);
    if (metrics_health_resource && metrics_stats_resource) {
        for (build_host_t* h = hosts; h; h = h->next) {
            const char* host_key2 = arena_strdup_n(&jt->arena,
                                                   h->name, h->name_len, false);
            const char* p_health = arena_strdup_n(&jt->arena, "/health", 7, false);
            const char* p_stats  = arena_strdup_n(&jt->arena, "/stats",  6, false);
            flat_insert(jt, host_key2, h->name_len, p_health, 7,
                        (resource_t*)metrics_health_resource);
            flat_insert(jt, host_key2, h->name_len, p_stats,  6,
                        (resource_t*)metrics_stats_resource);
        }
    }

    /* ---- Site aliases ---- */
    /* Parse wwwroot/_aliases: each line is "alias = target".
     * For each alias, duplicate all flat-table entries from the target
     * host under the alias hostname (sharing the same resource_t*). */
    {
        char aliases_path[4096];
        int apn = snprintf(aliases_path, sizeof(aliases_path), "%s/_aliases", wwwroot);
        if (apn > 0 && (size_t)apn < sizeof(aliases_path)) {
            FILE* af = fopen(aliases_path, "r");
            if (af) {
                char line[1024];
                while (fgets(line, sizeof(line), af)) {
                    /* Strip newline. */
                    size_t ll = strlen(line);
                    while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';
                    if (ll == 0 || line[0] == '#') continue;

                    /* Parse "alias = target" */
                    char* eq = strchr(line, '=');
                    if (!eq) {
                        metal_log("warn: _aliases: bad line (no '='): %s", line);
                        continue;
                    }
                    *eq = '\0';
                    /* Trim whitespace from alias (left side) */
                    char* alias = line;
                    while (*alias == ' ' || *alias == '\t') alias++;
                    char* ae = eq - 1;
                    while (ae > alias && (*ae == ' ' || *ae == '\t')) *ae-- = '\0';
                    /* Trim whitespace from target (right side) */
                    char* target = eq + 1;
                    while (*target == ' ' || *target == '\t') target++;
                    char* te = target + strlen(target) - 1;
                    while (te > target && (*te == ' ' || *te == '\t')) *te-- = '\0';

                    size_t alias_len = strlen(alias);
                    size_t target_len = strlen(target);
                    if (alias_len == 0 || target_len == 0 || alias_len > 253) {
                        metal_log("warn: _aliases: invalid alias/target: '%s' = '%s'", alias, target);
                        continue;
                    }

                    /* Lowercase both. */
                    metal_lower_inplace(alias, alias_len);
                    metal_lower_inplace(target, target_len);

                    /* Reject alias == target. */
                    if (alias_len == target_len && memcmp(alias, target, alias_len) == 0) {
                        metal_log("warn: _aliases: alias == target: '%s'", alias);
                        continue;
                    }

                    /* Verify target is a real host (not another alias). */
                    bool found_target = false;
                    for (build_host_t* h = hosts; h; h = h->next) {
                        if (h->name_len == target_len && memcmp(h->name, target, target_len) == 0) {
                            found_target = true;
                            break;
                        }
                    }
                    if (!found_target) {
                        metal_log("warn: _aliases: target host '%s' not found", target);
                        continue;
                    }

                    /* Reject alias that collides with a real host directory. */
                    bool collides = false;
                    for (build_host_t* h = hosts; h; h = h->next) {
                        if (h->name_len == alias_len && memcmp(h->name, alias, alias_len) == 0) {
                            collides = true;
                            break;
                        }
                    }
                    if (collides) {
                        metal_log("warn: _aliases: alias '%s' collides with real host", alias);
                        continue;
                    }

                    /* Duplicate flat-table entries from target under alias. */
                    const char* alias_key = arena_strdup_n(&jt->arena, alias, alias_len, false);
                    size_t duped = 0;
                    for (size_t i = 0; i < jt->cap; i++) {
                        flat_slot_t* s = &jt->slots[i];
                        if (!s->value) continue;
                        uint32_t s_host_len = s->lens >> 16;
                        uint32_t s_path_len = s->lens & 0xFFFF;
                        if (s_host_len == target_len &&
                            memcmp(s->host, target, target_len) == 0) {
                            const char* path_key = arena_strdup_n(&jt->arena, s->path, s_path_len, false);
                            flat_insert(jt, alias_key, alias_len, path_key, s_path_len, s->value);
                            duped++;
                        }
                    }

                    /* Register alias in known_hosts. */
                    if (jt->known_host_count >= 128)
                        metal_die("too many virtual hosts (max 128)");
                    jt->known_hosts[jt->known_host_count].name = alias_key;
                    jt->known_hosts[jt->known_host_count].len = alias_len;
                    jt->known_host_count++;

                    metal_log("  alias '%s' -> '%s': %zu resource(s) duplicated",
                              alias, target, duped);
                }
                fclose(af);
            }
        }
    }

    build_free(hosts);

    /* Release the unused tail of the arena back to the kernel BEFORE
     * we PROT_READ-freeze the rest. Typical sites save 25-30% of the
     * worst-case-bounded arena this way. */
    size_t cap_before_shrink = jt->arena.cap;
    if (!arena_shrink_to_fit(&jt->arena)) {
        metal_log("warn: arena_shrink_to_fit failed (continuing)");
    }

    if (!arena_freeze(&jt->arena)) {
        metal_log("warn: arena_freeze failed (continuing without PROT_READ)");
    }

    metal_log("picoweb: arena used %zu / %zu B (released %zu); %zu / %zu slots filled%s",
              arena_used(&jt->arena), jt->arena.cap,
              cap_before_shrink - jt->arena.cap,
              jt->size, jt->cap,
              no_gzip_enabled() ? " [no-gzip]" : "");
    return true;
}

/* ============================================================== */
/* Lookup                                                         */
/* ============================================================== */

const resource_t* jumptable_lookup(const jumptable_t* jt,
                                   const char* host, size_t host_len,
                                   const char* path, size_t path_len) {
    if (path_len == 0 || path[0] != '/') return NULL;
    return flat_lookup(jt, host, host_len, path, path_len);
}

__attribute__((cold))
bool jumptable_host_exists(const jumptable_t* jt,
                           const char* host, size_t host_len) {
    for (size_t i = 0; i < jt->known_host_count; i++) {
        if (jt->known_hosts[i].len == host_len &&
            memcmp(jt->known_hosts[i].name, host, host_len) == 0)
            return true;
    }
    return false;
}

/* Touch every page of a buffer so the kernel faults it in. Reads only,
 * accumulating into a volatile sink to keep the optimiser honest. */
static volatile uint64_t g_prewarm_sink;
__attribute__((cold))
static void prewarm_touch(const void* p, size_t len) {
    if (!p || len == 0) return;
    const unsigned char* b = (const unsigned char*)p;
    uint64_t acc = g_prewarm_sink;
    for (size_t i = 0; i < len; i += 4096) acc ^= b[i];
    acc ^= b[len - 1];
    g_prewarm_sink = acc;
}

__attribute__((cold))
static void prewarm_resource(const resource_t* r) {
    if (!r) return;
    prewarm_touch(r->head, r->head_len);
    prewarm_touch(r->body, r->body_len);
    if (r->compressed) {
        prewarm_touch(r->compressed->head, r->compressed->head_len);
        prewarm_touch(r->compressed->body, r->compressed->body_len);
    }
    if (r->brotli) {
        prewarm_touch(r->brotli->head, r->brotli->head_len);
        prewarm_touch(r->brotli->body, r->brotli->body_len);
    }
    if (r->chrome) {
        prewarm_touch(r->chrome->hdr, r->chrome->hdr_len);
        prewarm_touch(r->chrome->ftr, r->chrome->ftr_len);
    }
    prewarm_touch(r->wire_304, r->wire_304_len);
    prewarm_touch(r->link_hdr, r->link_hdr_len);
}

__attribute__((cold))
void jumptable_prewarm(const jumptable_t* jt) {
    if (!jt) return;
    uint64_t acc = g_prewarm_sink;
    size_t walked = 0;
    for (size_t i = 0; i < jt->cap; i++) {
        const flat_slot_t* s = &jt->slots[i];
        acc ^= s->hash ^ s->lens;
        if (!s->value) continue;
        prewarm_resource(s->value);
        walked++;
    }
    g_prewarm_sink = acc;
    prewarm_resource(jt->err_400);
    prewarm_resource(jt->err_404);
    prewarm_resource(jt->err_405);
    prewarm_resource(jt->err_409);
    prewarm_resource(jt->err_413);
    prewarm_resource(jt->err_414);
    prewarm_resource(jt->err_505);
    metal_log("jumptable: prewarmed %zu resources across %zu slots",
              walked, jt->cap);
}
