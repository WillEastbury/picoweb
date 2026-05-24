#ifndef METAL_HTTP_H
#define METAL_HTTP_H

#include <stddef.h>
#include <stdbool.h>

#include "jumptable.h"

typedef enum {
    HTTP_NEED_MORE = 0,
    HTTP_OK,
    HTTP_ERR_400,
    HTTP_ERR_405,
    HTTP_ERR_409,
    HTTP_ERR_413,
    HTTP_ERR_414,
    HTTP_ERR_505,
} http_result_t;

typedef enum {
    M_GET = 0, M_HEAD, M_POST, M_PUT, M_DELETE, M_OPTIONS, M_UNKNOWN
} http_method_t;

typedef struct {
    http_method_t method;
    char*  host;          /* points into read_buf, lowercased in-place */
    size_t host_len;
    char*  path;          /* points into read_buf */
    size_t path_len;
    bool   client_close;  /* Connection: close */
    bool   accept_pc;     /* Accept-Encoding contains picoweb-compress / BareMetal.Compress */
    bool   accept_br;     /* Accept-Encoding contains br (Brotli) */
    bool   has_leftover;  /* extra bytes after \r\n\r\n */
    size_t consumed;      /* total bytes consumed from buf */
    const char* if_none_match;   /* raw If-None-Match value (points into buf) */
    size_t if_none_match_len;
    const char* cookie;          /* raw Cookie header value (points into buf) */
    size_t cookie_len;
    bool   pw_auth_header;       /* X-PW-Auth: 1 */
    const char* origin;          /* raw Origin header value (points into buf) */
    size_t origin_len;
    const char* acr_headers;     /* Access-Control-Request-Headers value */
    size_t acr_headers_len;
    const char* pw_principal;    /* X-PW-Principal / X-Principal-Id value */
    size_t pw_principal_len;
    const char* pw_tenant;       /* X-PW-Tenant value */
    size_t pw_tenant_len;
    const char* score_token;     /* X-Score-Token value */
    size_t score_token_len;
    /* Content-Length value, parsed from header. 0 if header absent or
     * value was "0". On a valid request, body bytes (if any) live in the
     * caller buffer at offset `consumed` and have length `content_length`.
     * The HTTP parser does NOT itself consume the body. */
    size_t content_length;
} http_request_t;

/* Parse a request from buf[0..buf_len). On HTTP_NEED_MORE the caller
 * should read more bytes and call again. The buffer may be modified
 * in-place (host header lowercased, etc). */
http_result_t http_parse(char* buf, size_t buf_len, http_request_t* out);

/* Check if the client's If-None-Match header value matches our ETag.
 * Implements RFC 7232 weak comparison: W/ prefix stripped, comma-separated
 * list, wildcard (*) support. */
bool etag_matches(const char* inm, size_t inm_len, const char* etag);

/* Pick a response for a parse result + parsed request.
 *  *out_close_after  - the connection should close after this response
 *  *out_head_only    - send head only (no body); set for HEAD method */
const resource_t* http_select(const jumptable_t* jt,
                              http_result_t pr,
                              const http_request_t* req,
                              bool* out_close_after,
                              bool* out_head_only);

#endif
