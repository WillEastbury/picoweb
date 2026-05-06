#include "http.h"
#include "brotli.h"
#include "compress.h"
#include "util.h"

#include <ctype.h>
#include <string.h>

/* ============================================================== */
/* Small helpers                                                  */
/* ============================================================== */

#define MAX_URI_LEN 2048

static http_method_t classify_method(const char* m, size_t len) {
    if (len == 3 && memcmp(m, "GET", 3) == 0) return M_GET;
    if (len == 4 && memcmp(m, "HEAD", 4) == 0) return M_HEAD;
    if (len == 4 && memcmp(m, "POST", 4) == 0) return M_POST;
    if (len == 3 && memcmp(m, "PUT", 3) == 0) return M_PUT;
    if (len == 6 && memcmp(m, "DELETE", 6) == 0) return M_DELETE;
    return M_UNKNOWN;
}

static bool path_is_safe(const char* p, size_t len) {
    if (len == 0 || p[0] != '/') return false;
    if (len > MAX_URI_LEN) return false;
    /* Reject control chars and NUL */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c < 0x20 || c == 0x7f) return false;
    }
    /* Reject any ".." segment */
    for (size_t i = 0; i + 1 < len; i++) {
        if (p[i] == '.' && p[i + 1] == '.') {
            bool left_ok  = (i == 0) || p[i - 1] == '/';
            bool right_ok = (i + 2 == len) || p[i + 2] == '/';
            if (left_ok && right_ok) return false;
        }
    }
    return true;
}

/* Trim optional whitespace (SP/HT) from both ends. Returns new ptr +
 * length via *out_len. Operates in-place style on the same buffer. */
static const char* trim_ows(const char* s, size_t len, size_t* out_len) {
    size_t i = 0, j = len;
    while (i < j && (s[i] == ' ' || s[i] == '\t')) i++;
    while (j > i && (s[j - 1] == ' ' || s[j - 1] == '\t')) j--;
    *out_len = j - i;
    return s + i;
}

/* ============================================================== */
/* Parser                                                         */
/* ============================================================== */

http_result_t http_parse(char* buf, size_t buf_len, http_request_t* out) {
    memset(out, 0, sizeof(*out));

    /* Look for end of headers \r\n\r\n */
    if (buf_len < 4) return HTTP_NEED_MORE;
    char* end = NULL;
    /* memmem is GNU; it's available with _GNU_SOURCE on Linux */
    end = (char*)memmem(buf, buf_len, "\r\n\r\n", 4);
    if (!end) {
        /* If buffer is full and we haven't found end-of-headers, give up. */
        if (buf_len >= 8192) return HTTP_ERR_413;
        return HTTP_NEED_MORE;
    }
    size_t headers_len = (size_t)(end - buf) + 4; /* including \r\n\r\n */
    out->consumed = headers_len;
    out->has_leftover = (headers_len < buf_len);

    /* ---- Parse request line ---- */
    char* line_end = (char*)memchr(buf, '\r', headers_len);
    if (!line_end || line_end[1] != '\n') return HTTP_ERR_400;
    size_t line_len = (size_t)(line_end - buf);
    if (line_len == 0 || line_len > MAX_URI_LEN + 32) return HTTP_ERR_414;

    char* sp1 = (char*)memchr(buf, ' ', line_len);
    if (!sp1) return HTTP_ERR_400;
    size_t method_len = (size_t)(sp1 - buf);

    char* path_start = sp1 + 1;
    char* sp2 = (char*)memchr(path_start, ' ', line_len - method_len - 1);
    if (!sp2) return HTTP_ERR_400;
    size_t path_len = (size_t)(sp2 - path_start);

    char* version_start = sp2 + 1;
    size_t version_len = line_len - method_len - 1 - path_len - 1;
    if (version_len != 8 || memcmp(version_start, "HTTP/1.1", 8) != 0) {
        /* Reject HTTP/1.0 too — we only support 1.1 per requirements */
        return HTTP_ERR_505;
    }

    out->method = classify_method(buf, method_len);
    if (out->method == M_UNKNOWN) return HTTP_ERR_405;

    if (!path_is_safe(path_start, path_len)) {
        return (path_len > MAX_URI_LEN) ? HTTP_ERR_414 : HTTP_ERR_400;
    }
    /* Strip query string (we don't serve dynamic content). */
    char* q = (char*)memchr(path_start, '?', path_len);
    if (q) path_len = (size_t)(q - path_start);

    out->path = path_start;
    out->path_len = path_len;

    /* ---- Scan headers ---- */
    char* p = line_end + 2; /* past CRLF of request line */
    /* hdr_end is one past the last header's CRLF, i.e., the start of
     * the terminating empty line. Searching [p, hdr_end) finds each
     * header line's trailing \r within range. */
    char* hdr_end = end + 2;
    int host_seen = 0;
    bool body_present = false;

    while (p < hdr_end) {
        char* eol = (char*)memchr(p, '\r', (size_t)(hdr_end - p));
        if (!eol || eol[1] != '\n') return HTTP_ERR_400;
        size_t hl = (size_t)(eol - p);
        char* colon = (char*)memchr(p, ':', hl);
        if (!colon) return HTTP_ERR_400;
        size_t name_len = (size_t)(colon - p);
        const char* val = colon + 1;
        size_t val_len = hl - name_len - 1;
        size_t tl = 0;
        const char* tval = trim_ows(val, val_len, &tl);

        if (metal_ieq(p, name_len, "Host", 4)) {
            if (host_seen++) return HTTP_ERR_400;
            /* Strip :port */
            const char* colon2 = (const char*)memchr(tval, ':', tl);
            size_t hostlen = colon2 ? (size_t)(colon2 - tval) : tl;
            if (hostlen == 0 || hostlen > 253) return HTTP_ERR_400;
            /* Lowercase in place. tval points into buf (writable). */
            metal_lower_inplace((char*)(uintptr_t)tval, hostlen);
            /* Validate hostname charset */
            for (size_t i = 0; i < hostlen; i++) {
                char c = tval[i];
                bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                       || c == '.' || c == '-';
                if (!ok) return HTTP_ERR_400;
            }
            out->host = (char*)(uintptr_t)tval;
            out->host_len = hostlen;
        } else if (metal_ieq(p, name_len, "Content-Length", 14)) {
            /* Reject any non-zero CL — we don't drain bodies in v1. */
            for (size_t i = 0; i < tl; i++) {
                if (tval[i] != '0') { body_present = true; break; }
            }
            if (tl == 0) body_present = true;
        } else if (metal_ieq(p, name_len, "Transfer-Encoding", 17)) {
            body_present = true;
        } else if (metal_ieq(p, name_len, "Connection", 10)) {
            /* Connection is a comma-separated token list; honour any
             * "close" token in case-insensitive form. */
            size_t k = 0;
            while (k < tl) {
                while (k < tl && (tval[k] == ' ' || tval[k] == '\t' ||
                                  tval[k] == ',')) k++;
                size_t s = k;
                while (k < tl && tval[k] != ',') k++;
                size_t e = k;
                while (e > s && (tval[e - 1] == ' ' || tval[e - 1] == '\t')) e--;
                if (e - s == 5 && metal_ieq(tval + s, 5, "close", 5)) {
                    out->client_close = true;
                    break;
                }
            }
        } else if (metal_ieq(p, name_len, "Accept-Encoding", 15)) {
            /* Substring scan for tokens we serve. Token names are
             * exact-form (case-sensitive); the rest of the value
             * (q-values, other tokens) is ignored. */
            if (metal_compress_accepted(tval, tl)) out->accept_pc = true;
            if (brotli_accepted(tval, tl)) out->accept_br = true;
        }
        p = eol + 2;
    }

    if (host_seen == 0) return HTTP_ERR_400;

    /* If the request declared a body, force-close after responding —
     * we can't safely parse the next request because we won't drain. */
    if (body_present) out->client_close = true;
    /* Note: we do NOT force-close on leftover bytes. The server compacts
     * the read buffer using out->consumed and processes one request at
     * a time; any leftover bytes are simply the start of the next
     * request, which we'll parse on the next loop iteration. */

    return HTTP_OK;
}

/* ============================================================== */
/* Response selection                                             */
/* ============================================================== */

const resource_t* http_select(const jumptable_t* jt,
                              http_result_t pr,
                              const http_request_t* req,
                              bool* out_close_after,
                              bool* out_head_only) {
    *out_head_only = false;

    /* Parse-level errors: cannot trust framing for next request. */
    switch (pr) {
        case HTTP_ERR_400: *out_close_after = true; return jt->err_400;
        case HTTP_ERR_413: *out_close_after = true; return jt->err_413;
        case HTTP_ERR_414: *out_close_after = true; return jt->err_414;
        case HTTP_ERR_505: *out_close_after = true; return jt->err_505;
        case HTTP_ERR_405:
            /* Unknown method — close (could be anything on the wire next) */
            *out_close_after = true;
            return jt->err_405;
        case HTTP_OK:
        case HTTP_NEED_MORE:
            break;
    }

    /* HTTP_OK from here */
    *out_close_after = req->client_close;

    if (req->method == M_POST || req->method == M_PUT || req->method == M_DELETE) {
        /* Allowed methods, but unsupported in v1. Keep-alive ok if
         * request was framed properly (no body declared). */
        return jt->err_405;
    }
    if (req->method != M_GET && req->method != M_HEAD) {
        *out_close_after = true;
        return jt->err_405;
    }

    *out_head_only = (req->method == M_HEAD);

    const resource_t* r = jumptable_lookup(jt, req->host, req->host_len,
                                           req->path, req->path_len);
    if (!r) return jt->err_404;
    return r;
}
