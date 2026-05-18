/* preload.c — see preload.h.
 *
 * The parser is deliberately a small, single-pass HTML scanner that
 * understands just enough of the spec to be safe against the dialect
 * we generate: it knows about quoted/unquoted attributes, raw-text
 * elements (<script>, <style>, <textarea>), comments, and CDATA
 * sections. It does NOT attempt to be a browser-grade tokenizer. */

#include "preload.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* --- small character helpers ----------------------------------------- */

static inline int ci_eq(const char* a, size_t alen, const char* lit) {
    size_t L = strlen(lit);
    if (alen != L) return 0;
    for (size_t i = 0; i < L; i++) {
        char c = a[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != lit[i]) return 0;
    }
    return 1;
}

static inline int ci_starts(const char* p, size_t plen, const char* lit) {
    size_t L = strlen(lit);
    if (plen < L) return 0;
    for (size_t i = 0; i < L; i++) {
        char c = p[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != lit[i]) return 0;
    }
    return 1;
}

static inline int is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

/* skip whitespace; returns new offset */
static size_t skip_ws(const char* s, size_t i, size_t n) {
    while (i < n && is_ws(s[i])) i++;
    return i;
}

/* --- attribute extraction -------------------------------------------- */

typedef struct {
    const char* base;
    size_t      len;
} sv_t;

static sv_t sv_make(const char* p, size_t l) { sv_t v = { p, l }; return v; }
static int  sv_empty(sv_t v) { return v.len == 0; }

/* Find attribute named `name` (case-insensitive) within tag bytes
 * `tag[0..tlen)`. Returns the value as an sv_t into the original
 * buffer (no allocation). Empty if not found or value is empty. */
static sv_t find_attr(const char* tag, size_t tlen, const char* name) {
    size_t nlen = strlen(name);
    size_t i = 0;
    /* skip the tag name itself: first run of non-whitespace, non-'>' */
    while (i < tlen && !is_ws(tag[i]) && tag[i] != '>' && tag[i] != '/') i++;
    while (i < tlen) {
        i = skip_ws(tag, i, tlen);
        if (i >= tlen) break;
        if (tag[i] == '/' || tag[i] == '>') break;
        /* attribute name */
        size_t name_start = i;
        while (i < tlen && !is_ws(tag[i]) && tag[i] != '=' &&
               tag[i] != '>' && tag[i] != '/') i++;
        size_t name_end = i;
        i = skip_ws(tag, i, tlen);
        sv_t val = sv_make(NULL, 0);
        if (i < tlen && tag[i] == '=') {
            i++;
            i = skip_ws(tag, i, tlen);
            if (i < tlen && (tag[i] == '"' || tag[i] == '\'')) {
                char q = tag[i++];
                size_t v_start = i;
                while (i < tlen && tag[i] != q) i++;
                val = sv_make(tag + v_start, i - v_start);
                if (i < tlen) i++;
            } else {
                size_t v_start = i;
                while (i < tlen && !is_ws(tag[i]) && tag[i] != '>') i++;
                val = sv_make(tag + v_start, i - v_start);
            }
        }
        size_t this_nlen = name_end - name_start;
        if (this_nlen == nlen) {
            int match = 1;
            for (size_t k = 0; k < nlen; k++) {
                char c = tag[name_start + k];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                if (c != name[k]) { match = 0; break; }
            }
            if (match) return val;
        }
    }
    return sv_make(NULL, 0);
}

/* Check if a value (case-insensitive) appears as a token in a
 * space-separated attribute value (e.g. rel="preload stylesheet"). */
static int has_token(sv_t v, const char* tok) {
    size_t tlen = strlen(tok);
    size_t i = 0;
    while (i < v.len) {
        while (i < v.len && is_ws(v.base[i])) i++;
        size_t s = i;
        while (i < v.len && !is_ws(v.base[i])) i++;
        size_t e = i;
        if (e - s == tlen) {
            int match = 1;
            for (size_t k = 0; k < tlen; k++) {
                char c = v.base[s + k];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                if (c != tok[k]) { match = 0; break; }
            }
            if (match) return 1;
        }
    }
    return 0;
}

/* --- URL classification ---------------------------------------------- */

typedef enum {
    URL_INVALID = 0,
    URL_SAME_ORIGIN,    /* "/foo" or "https://<host>/foo" */
    URL_CROSS_ORIGIN    /* "https://other.example/foo" */
} url_class_t;

/* Check that the URL contains no characters that would corrupt the
 * Link header line. RFC 8288 link-target inside <...> is permissive,
 * but CR/LF/NUL/control chars are out. */
static int url_safe(sv_t u) {
    if (u.len == 0) return 0;
    for (size_t i = 0; i < u.len; i++) {
        unsigned char c = (unsigned char)u.base[i];
        if (c < 0x20 || c == 0x7f || c == '"' || c == '<' || c == '>')
            return 0;
    }
    return 1;
}

/* Classify the URL relative to `host`. Returns the canonical Link target
 * string in `out` (slice into the original URL for same-origin paths,
 * or the origin "scheme://host" for cross-origin preconnect). */
static url_class_t classify_url(sv_t u,
                                const char* host, size_t host_len,
                                sv_t* out_target) {
    *out_target = sv_make(NULL, 0);
    if (!url_safe(u)) return URL_INVALID;
    /* fragments / data URIs / mailto / javascript / about */
    if (u.base[0] == '#') return URL_INVALID;
    if (u.len >= 5 && (ci_starts(u.base, u.len, "data:") ||
                       ci_starts(u.base, u.len, "blob:") ||
                       ci_starts(u.base, u.len, "about"))) return URL_INVALID;
    if (u.len >= 7 && (ci_starts(u.base, u.len, "mailto:") ||
                       ci_starts(u.base, u.len, "javascr"))) return URL_INVALID;

    /* Same-origin relative path: "/...". We only emit absolute-path
     * refs as preload (not "foo.css" relative without leading slash,
     * because the request path context is unknown at this layer). */
    if (u.base[0] == '/' && (u.len < 2 || u.base[1] != '/')) {
        *out_target = u;
        return URL_SAME_ORIGIN;
    }

    /* Scheme-relative or absolute URL: split off scheme and authority. */
    const char* p = u.base;
    size_t      n = u.len;
    size_t      scheme_end = 0;
    if (n >= 8 && (ci_starts(p, n, "https://") || ci_starts(p, n, "http://"))) {
        scheme_end = ci_starts(p, n, "https://") ? 8 : 7;
    } else if (n >= 2 && p[0] == '/' && p[1] == '/') {
        scheme_end = 2;
    } else {
        return URL_INVALID;
    }
    /* authority runs to next '/' or end */
    size_t auth_start = scheme_end;
    size_t auth_end = auth_start;
    while (auth_end < n && p[auth_end] != '/' && p[auth_end] != '?' &&
           p[auth_end] != '#') auth_end++;
    if (auth_end == auth_start) return URL_INVALID;

    if (host_len > 0 && (auth_end - auth_start) == host_len &&
        strncasecmp(p + auth_start, host, host_len) == 0) {
        /* Same origin (host match). Emit the absolute URL as-is. */
        *out_target = u;
        return URL_SAME_ORIGIN;
    }
    /* Cross origin: target is just scheme + authority (origin) for
     * rel=preconnect. */
    *out_target = sv_make(p, auth_end);
    return URL_CROSS_ORIGIN;
}

/* --- hint records ---------------------------------------------------- */

typedef enum {
    HINT_PRECONNECT     = 0,   /* lowest priority; tiny payload */
    HINT_AS_IMAGE       = 1,
    HINT_AS_FONT        = 2,
    HINT_AS_SCRIPT      = 3,
    HINT_AS_STYLE       = 4,   /* highest: render-blocking */
    HINT_MODULEPRELOAD  = 5,
} hint_prio_t;

typedef struct {
    sv_t        target;        /* URL (slice into source HTML) */
    sv_t        as_val;        /* "style", "script", ... empty for preconnect */
    sv_t        type;          /* MIME type if known (e.g. "font/woff2") */
    sv_t        media;
    int         crossorigin;   /* 0 = none, 1 = present (anonymous) */
    int         is_modulepreload;
    int         is_preconnect;
    hint_prio_t prio;
} hint_t;

#define MAX_HINTS 64

/* Auto-derive `as=` from a tag/extension. Returns "" if unknown. */
static const char* default_as_for_link(sv_t href, sv_t rel, sv_t type) {
    if (has_token(rel, "stylesheet")) return "style";
    if (has_token(rel, "preload")) return NULL;  /* preserve explicit as= */
    /* For rel=preload without an explicit as, fall back to extension. */
    (void)href; (void)type;
    return "";
}

/* Guess MIME type for a font URL by extension. */
static const char* font_mime_for_url(sv_t u) {
    if (u.len >= 6 &&
        (memcmp(u.base + u.len - 6, ".woff2", 6) == 0 ||
         memcmp(u.base + u.len - 6, ".WOFF2", 6) == 0)) return "font/woff2";
    if (u.len >= 5 &&
        (memcmp(u.base + u.len - 5, ".woff", 5) == 0 ||
         memcmp(u.base + u.len - 5, ".WOFF", 5) == 0)) return "font/woff";
    if (u.len >= 4 &&
        (memcmp(u.base + u.len - 4, ".ttf", 4) == 0 ||
         memcmp(u.base + u.len - 4, ".TTF", 4) == 0)) return "font/ttf";
    return NULL;
}

/* Detect if a URL "looks like" a font (woff/woff2/ttf/otf). */
static int looks_like_font(sv_t u) {
    if (u.len < 4) return 0;
    const char* tail = u.base + u.len - 4;
    return (tail[0] == '.' &&
            ((tail[1] == 't' || tail[1] == 'T') ||
             (tail[1] == 'o' || tail[1] == 'O') ||
             (u.len >= 5 && (u.base[u.len-5] == 'w' || u.base[u.len-5] == 'W'))));
}

/* --- emit Link header lines ----------------------------------------- */

/* Append printf-formatted bytes to (out,off,cap). Returns 0 on success
 * or -1 on overflow (in which case `*off` is unchanged). */
static int append_fmt(char* out, size_t* off, size_t cap, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *off, cap > *off ? cap - *off : 0, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= (cap - *off)) return -1;
    *off += (size_t)n;
    return 0;
}

/* Emit one fully-formed "Link: ...\r\n" line for a hint. Returns 0 on
 * success, -1 if the line would exceed `out_cap - *off`. */
static int emit_hint(const hint_t* h, char* out, size_t* off, size_t out_cap) {
    size_t saved = *off;
    if (h->is_preconnect) {
        if (append_fmt(out, off, out_cap, "Link: <%.*s>; rel=preconnect",
                       (int)h->target.len, h->target.base) != 0) goto fail;
        if (h->crossorigin &&
            append_fmt(out, off, out_cap, "; crossorigin") != 0) goto fail;
    } else if (h->is_modulepreload) {
        if (append_fmt(out, off, out_cap,
                       "Link: <%.*s>; rel=modulepreload",
                       (int)h->target.len, h->target.base) != 0) goto fail;
        if (h->crossorigin &&
            append_fmt(out, off, out_cap, "; crossorigin") != 0) goto fail;
    } else {
        if (append_fmt(out, off, out_cap,
                       "Link: <%.*s>; rel=preload",
                       (int)h->target.len, h->target.base) != 0) goto fail;
        if (!sv_empty(h->as_val) &&
            append_fmt(out, off, out_cap, "; as=%.*s",
                       (int)h->as_val.len, h->as_val.base) != 0) goto fail;
        if (!sv_empty(h->type) &&
            append_fmt(out, off, out_cap, "; type=\"%.*s\"",
                       (int)h->type.len, h->type.base) != 0) goto fail;
        if (h->crossorigin &&
            append_fmt(out, off, out_cap, "; crossorigin") != 0) goto fail;
        if (!sv_empty(h->media) &&
            append_fmt(out, off, out_cap, "; media=\"%.*s\"",
                       (int)h->media.len, h->media.base) != 0) goto fail;
    }
    if (append_fmt(out, off, out_cap, "\r\n") != 0) goto fail;
    return 0;
fail:
    *off = saved;
    return -1;
}

/* --- dedupe ---------------------------------------------------------- */

static int sv_eq(sv_t a, sv_t b) {
    if (a.len != b.len) return 0;
    return memcmp(a.base, b.base, a.len) == 0;
}

static int hint_eq(const hint_t* a, const hint_t* b) {
    return a->is_preconnect == b->is_preconnect &&
           a->is_modulepreload == b->is_modulepreload &&
           a->crossorigin == b->crossorigin &&
           sv_eq(a->target, b->target) &&
           sv_eq(a->as_val, b->as_val) &&
           sv_eq(a->type, b->type) &&
           sv_eq(a->media, b->media);
}

/* --- the scanner ----------------------------------------------------- */

/* Skip the contents of a raw-text element (e.g. <script>, <style>) up
 * to and including its </Tag> close. Returns the offset after </Tag>
 * (or `n` if not found). */
static size_t skip_raw_text(const char* s, size_t i, size_t n,
                             const char* close_tag) {
    size_t cl = strlen(close_tag);
    while (i < n) {
        if (s[i] == '<' && i + 1 < n && s[i+1] == '/') {
            if (i + 2 + cl <= n && ci_starts(s + i + 2, n - i - 2, close_tag)) {
                size_t j = i + 2 + cl;
                /* skip to '>' */
                while (j < n && s[j] != '>') j++;
                if (j < n) j++;
                return j;
            }
        }
        i++;
    }
    return n;
}

/* Skip an HTML comment "<!-- ... -->" or CDATA section "<![CDATA[...]]>"
 * starting at i (where s[i]=='<' and s[i+1]=='!'). Returns offset past
 * the close. If the prefix doesn't actually match, returns i+1. */
static size_t skip_comment(const char* s, size_t i, size_t n) {
    if (i + 4 <= n && memcmp(s + i, "<!--", 4) == 0) {
        size_t j = i + 4;
        while (j + 3 <= n && memcmp(s + j, "-->", 3) != 0) j++;
        return (j + 3 <= n) ? (j + 3) : n;
    }
    if (i + 9 <= n && memcmp(s + i, "<![CDATA[", 9) == 0) {
        size_t j = i + 9;
        while (j + 3 <= n && memcmp(s + j, "]]>", 3) != 0) j++;
        return (j + 3 <= n) ? (j + 3) : n;
    }
    /* Other "<!..." (e.g. doctype): skip to '>' */
    size_t j = i + 2;
    while (j < n && s[j] != '>') j++;
    return (j < n) ? (j + 1) : n;
}

/* Add a hint to the array if not duplicate. Returns index added or -1
 * if full / duplicate. */
static int hints_add_unique(hint_t* hints, int* n, const hint_t* h) {
    for (int i = 0; i < *n; i++) {
        if (hint_eq(&hints[i], h)) return -1;
    }
    if (*n >= MAX_HINTS) return -1;
    hints[*n] = *h;
    return (*n)++;
}

/* Process one open tag. `tag` points at the byte after '<', `tlen`
 * runs to (but not including) the closing '>'. */
static void process_tag(const char* tag, size_t tlen,
                        const char* host, size_t host_len,
                        hint_t* hints, int* n_hints) {
    /* tag-name */
    size_t i = 0;
    while (i < tlen && !is_ws(tag[i]) && tag[i] != '/' && tag[i] != '>') i++;
    sv_t name = sv_make(tag, i);

    sv_t href_attr = sv_make(NULL, 0);
    sv_t src_attr  = sv_make(NULL, 0);
    sv_t rel_attr  = find_attr(tag, tlen, "rel");
    sv_t as_attr   = find_attr(tag, tlen, "as");
    sv_t type_attr = find_attr(tag, tlen, "type");
    sv_t media     = find_attr(tag, tlen, "media");
    sv_t cors_attr = find_attr(tag, tlen, "crossorigin");
    /* `crossorigin` is a boolean attribute; presence (with empty or any
     * value) counts as "anonymous" CORS mode. */
    int crossorigin = (cors_attr.base != NULL);

    hint_t h;
    memset(&h, 0, sizeof(h));
    h.media = media;
    h.crossorigin = crossorigin;

    if (ci_eq(name.base, name.len, "link")) {
        href_attr = find_attr(tag, tlen, "href");
        if (sv_empty(href_attr)) return;
        /* Skip non-preloadable rel values. */
        if (has_token(rel_attr, "canonical") ||
            has_token(rel_attr, "manifest") ||
            has_token(rel_attr, "icon") ||
            has_token(rel_attr, "shortcut") ||
            has_token(rel_attr, "alternate") ||
            has_token(rel_attr, "dns-prefetch") ||
            has_token(rel_attr, "prerender") ||
            has_token(rel_attr, "prefetch")) return;
        h.target = href_attr;
        if (has_token(rel_attr, "modulepreload")) {
            h.is_modulepreload = 1;
            h.prio = HINT_MODULEPRELOAD;
        } else if (has_token(rel_attr, "preload")) {
            /* Preserve explicit as=. Skip if missing — without `as`
             * the browser doesn't know how to prioritize the fetch. */
            if (sv_empty(as_attr)) return;
            h.as_val = as_attr;
            h.type = type_attr;
            if (ci_eq(as_attr.base, as_attr.len, "style"))      h.prio = HINT_AS_STYLE;
            else if (ci_eq(as_attr.base, as_attr.len, "script")) h.prio = HINT_AS_SCRIPT;
            else if (ci_eq(as_attr.base, as_attr.len, "font"))   h.prio = HINT_AS_FONT;
            else                                                 h.prio = HINT_AS_IMAGE;
        } else if (has_token(rel_attr, "stylesheet") ||
                   has_token(rel_attr, "preconnect") /* see below */) {
            if (has_token(rel_attr, "stylesheet")) {
                h.as_val = sv_make("style", 5);
                h.prio = HINT_AS_STYLE;
            } else {
                /* Author already declared preconnect — pass through. */
                h.is_preconnect = 1;
                h.prio = HINT_PRECONNECT;
            }
        } else {
            return;
        }
    } else if (ci_eq(name.base, name.len, "script")) {
        src_attr = find_attr(tag, tlen, "src");
        if (sv_empty(src_attr)) return;
        sv_t typev = type_attr;
        h.target = src_attr;
        if (!sv_empty(typev) && ci_eq(typev.base, typev.len, "module")) {
            h.is_modulepreload = 1;
            h.prio = HINT_MODULEPRELOAD;
        } else {
            h.as_val = sv_make("script", 6);
            h.prio = HINT_AS_SCRIPT;
        }
    } else if (ci_eq(name.base, name.len, "img")) {
        src_attr = find_attr(tag, tlen, "src");
        if (sv_empty(src_attr)) return;
        h.target = src_attr;
        h.as_val = sv_make("image", 5);
        h.prio = HINT_AS_IMAGE;
    } else if (ci_eq(name.base, name.len, "source")) {
        src_attr = find_attr(tag, tlen, "src");
        if (sv_empty(src_attr)) return;
        h.target = src_attr;
        h.as_val = sv_make("image", 5);
        h.prio = HINT_AS_IMAGE;
    } else {
        return;
    }

    sv_t target_canon;
    url_class_t cls = classify_url(h.target, host, host_len, &target_canon);
    if (cls == URL_INVALID) return;
    h.target = target_canon;
    if (cls == URL_CROSS_ORIGIN) {
        /* Cross-origin: downgrade to preconnect. Don't speculatively
         * fetch arbitrary third-party bytes. */
        h.is_preconnect = 1;
        h.is_modulepreload = 0;
        h.as_val = sv_make(NULL, 0);
        h.type = sv_make(NULL, 0);
        h.media = sv_make(NULL, 0);
        h.crossorigin = 1;  /* preconnect for CORS-mode subresources */
        h.prio = HINT_PRECONNECT;
    } else {
        /* Same origin: enrich font hints with type & crossorigin. */
        if (!h.is_preconnect && !h.is_modulepreload &&
            ci_eq(h.as_val.base, h.as_val.len, "font")) {
            const char* mt = font_mime_for_url(h.target);
            if (mt && sv_empty(h.type)) h.type = sv_make(mt, strlen(mt));
            h.crossorigin = 1;
        }
        /* If as="font" was inferred from URL extension on a stylesheet/
         * script branch, that won't happen — but if a <link rel=preload
         * as=font> is missing crossorigin, we enforce it. */
        (void)looks_like_font;
        (void)default_as_for_link;
    }

    (void)hints_add_unique(hints, n_hints, &h);
}

size_t pw_preload_extract(const char* html, size_t html_len,
                          const char* host, size_t host_len,
                          char* out, size_t out_cap) {
    if (!html || !out || out_cap == 0) return 0;

    hint_t hints[MAX_HINTS];
    int n_hints = 0;

    size_t i = 0;
    while (i < html_len) {
        char c = html[i];
        if (c != '<') { i++; continue; }
        if (i + 1 >= html_len) break;
        char d = html[i+1];

        /* Comment / CDATA / doctype */
        if (d == '!') { i = skip_comment(html, i, html_len); continue; }

        /* End tag — just skip past '>' */
        if (d == '/') {
            size_t j = i + 2;
            while (j < html_len && html[j] != '>') j++;
            i = (j < html_len) ? (j + 1) : html_len;
            continue;
        }

        /* Open tag — find tag name to detect raw-text elements. */
        size_t name_start = i + 1;
        size_t j = name_start;
        while (j < html_len && !is_ws(html[j]) && html[j] != '>' &&
               html[j] != '/') j++;
        size_t name_len = j - name_start;
        /* Find end of open tag '>'. */
        size_t tag_end = j;
        while (tag_end < html_len && html[tag_end] != '>') tag_end++;
        if (tag_end >= html_len) break;

        process_tag(html + name_start, tag_end - name_start,
                    host, host_len, hints, &n_hints);

        size_t after = tag_end + 1;
        if (ci_eq(html + name_start, name_len, "script") ||
            ci_eq(html + name_start, name_len, "style") ||
            ci_eq(html + name_start, name_len, "textarea")) {
            const char* close = ci_eq(html + name_start, name_len, "script")   ? "script"   :
                                ci_eq(html + name_start, name_len, "style")    ? "style"    :
                                                                                  "textarea";
            after = skip_raw_text(html, after, html_len, close);
        }
        i = after;
    }

    if (n_hints == 0) return 0;

    /* Try to fit all hints; if not, drop lowest-priority categories
     * iteratively. Simple insertion sort by priority desc, then dedupe
     * suffix to the cap. */
    for (int a = 1; a < n_hints; a++) {
        hint_t tmp = hints[a];
        int b = a - 1;
        while (b >= 0 && hints[b].prio < tmp.prio) {
            hints[b+1] = hints[b];
            b--;
        }
        hints[b+1] = tmp;
    }

    if (out_cap > PW_PRELOAD_HEADER_CAP) out_cap = PW_PRELOAD_HEADER_CAP;

    size_t off = 0;
    for (int idx = 0; idx < n_hints; idx++) {
        if (emit_hint(&hints[idx], out, &off, out_cap) != 0) {
            /* Out of space — stop adding. Higher-prio entries are
             * already in. */
            break;
        }
    }
    return off;
}
