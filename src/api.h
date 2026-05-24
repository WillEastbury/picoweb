#ifndef METAL_API_H
#define METAL_API_H

/* Simple JSON-file CRUD API for picoweb.
 *
 * Routes (with --api-prefix=/api/, --api-root=./api-data):
 *   GET    /api/{coll}/{id}    -> 200 body | 404
 *   HEAD   /api/{coll}/{id}    -> 200 (Content-Length only) | 404
 *   PUT    /api/{coll}/{id}    -> 204 (atomic create-or-replace)
 *   POST   /api/{coll}         -> 201 + Location (auto-generated 32-char id)
 *   POST   /api/{coll}/{id}    -> 201 if created; 409 if exists
 *   DELETE /api/{coll}/{id}    -> 204 | 404
 *
 * Constraints (v1, "raw json files, no query, no indexing"):
 *   - {coll} and {id} must match  [A-Za-z0-9_-]{1,64}
 *   - Request body cap: API_REQ_BODY_CAP (fits in the per-conn read buffer)
 *   - Response body cap (GET file size): API_RESP_BODY_CAP
 *   - No JSON syntax validation: bytes are stored verbatim
 *   - No If-Match / ETag concurrency control
 *   - Each worker writes via tempfile + rename for atomic replace
 *   - Filesystem ops are dirfd-anchored with openat()/renameat()/unlinkat()
 *     and O_NOFOLLOW on opened components to avoid symlink traversal
 *   - POST with explicit id uses O_CREAT|O_EXCL for race-safe "create-only"
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "http.h"  /* http_method_t */

/* Caps. These are tuned so a request body fits inside METAL_READ_BUF
 * after typical request headers (~1.5KB). Bumping these requires a
 * matching bump to METAL_READ_BUF (or per-conn dynamic allocation,
 * deferred). */
#define API_REQ_BODY_CAP   6144
#define API_RESP_BODY_CAP  (1u << 20)  /* 1 MiB read cap on GET */
#define API_HEAD_CAP       1024
#define API_NAME_CAP       64

/* Response built by api_dispatch. body is heap-owned iff body_owned is
 * true; caller must invoke api_resp_release() once the bytes are no
 * longer referenced by any iovec. */
typedef struct {
    int    status;                /* 200 / 201 / 204 / 400 / 404 / 405 / 409 / 413 / 415 / 500 */
    char   head[API_HEAD_CAP];    /* status line + headers, ends with "\r\n" (no final blank) */
    size_t head_len;
    char*  body;                  /* may be NULL; not necessarily NUL-terminated */
    size_t body_len;
    bool   body_owned;            /* true => api_resp_release frees(body) */
} api_resp_t;

typedef struct {
    char principal_id[128];  /* request principal id resolved from session cookie */
    char tenant_id[64];      /* tenant id from first host component */
    char tenant_system[8];   /* dev / qa / prod from second host component */
    char client_ip[64];      /* peer IP for rate limiting; empty when unknown */
} api_request_context_t;

/* Configure once on the main thread before workers spawn. Creates root
 * dir if missing. Both arguments are duplicated. Passing NULL/empty for
 * root disables the API entirely (api_path_matches will always return
 * false). prefix MUST start and end with '/' (e.g. "/api/"). */
void api_init(const char* root_dir, const char* prefix);

/* True iff API is enabled and `path` starts with the configured prefix.
 * The prefix is required to end with '/' so "/api/" never matches a
 * literal "/api2/foo". */
bool api_path_matches(const char* path, size_t path_len);

/* True iff the API is enabled (root configured). */
bool api_enabled(void);
bool api_picowal_enabled(void);

/* Largest request body the API will accept. Useful for the dispatcher
 * to short-circuit oversize uploads before reading them. */
size_t api_max_request_body(void);

/* Optional raw-volume picowal backend mounted under a dedicated prefix
 * (default "/wal/"). This can be enabled alongside the JSON file backend. */
bool api_picowal_init(const char* device_path, uint64_t volume_bytes,
                      const char* prefix, bool format);
void api_picowal_set_public(bool public_routes);

/* Optional OIDC-backed cookie auth for picowal routes. When enabled,
 * non-auth picowal endpoints require an authenticated session cookie.
 * `cookie_ttl_sec` controls short-lived session duration.
 * `google_client_id` / `entra_client_id` are used to validate provider tokens.
 * `entra_tenant` is optional (NULL/empty disables tenant pinning). */
bool api_oidc_init(bool cookie_auth_enabled, uint32_t cookie_ttl_sec,
                   const char* google_client_id,
                   const char* entra_client_id,
                   const char* entra_tenant);

/* Resolve principal id from the pw_session cookie. Returns true on
 * success and writes a NUL-terminated principal id into out_principal. */
bool api_principal_from_cookie(const char* cookie, size_t cookie_len,
                               char* out_principal, size_t out_cap);

/* Apply CORS headers to an API response for a given request origin.
 * No-op when origin is absent/invalid. */
void api_apply_cors(api_resp_t* resp,
                    const char* origin, size_t origin_len,
                    const char* acr_headers, size_t acr_headers_len);

/* Perform the request and populate *resp. Always succeeds (errors land
 * as 4xx/5xx in resp->status). The caller must initialise resp to all
 * zeros before calling. The body buffer (if any) lives until
 * api_resp_release(). */
void api_dispatch(http_method_t method,
                  const char* path, size_t path_len,
                  const char* body, size_t body_len,
                  const char* cookie, size_t cookie_len,
                  bool has_pw_auth_header,
                  const char* score_token, size_t score_token_len,
                  const api_request_context_t* req_ctx,
                  api_resp_t* resp);

/* Release any heap memory owned by resp. Safe to call multiple times;
 * safe on an all-zero resp. */
void api_resp_release(api_resp_t* resp);

#endif
