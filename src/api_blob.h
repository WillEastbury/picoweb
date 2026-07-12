#ifndef METAL_API_BLOB_H
#define METAL_API_BLOB_H

/* Content-addressed HTTPS blob store, mounted into picoweb's existing
 * TLS-terminating API layer under a configurable prefix (default
 * "/blob/"). Reuses picoweb as the base server: connection handling,
 * TLS termination, and request framing are all picoweb's; this module
 * only supplies the storage semantics.
 *
 * Routes:
 *   POST   {prefix}            body=raw bytes -> 201 Created,
 *                               Location: {prefix}<sha256-hex>,
 *                               body: <sha256-hex>
 *   GET    {prefix}<hash>      -> 200 + raw bytes | 404
 *   HEAD   {prefix}<hash>      -> 200 (Content-Length only) | 404
 *   DELETE {prefix}<hash>      -> 204 | 404
 *
 * Blobs are named by their own SHA-256 (computed server-side on POST),
 * sharded into <prefix-root>/<first-2-hex-chars>/<hash> so the on-disk
 * path is never derived from client-controlled input. Writes are
 * tempfile + rename for atomic create, anchored to a root dirfd with
 * O_NOFOLLOW to avoid symlink traversal, matching the JSON-file API's
 * security posture in api.c.
 *
 * Because this module serves arbitrary binary payloads, it is only
 * ever mounted on the TLS worker: main.c refuses --blob-root unless
 * --tls-cert/--tls-key are also supplied, so blob data never traverses
 * plaintext HTTP.
 */

#include <stddef.h>
#include <stdbool.h>

#include "http.h"
#include "api.h"

bool api_blob_enabled(void);

/* Configure once on the main thread before workers spawn. Creates
 * root_dir if missing. prefix must start and end with '/'. Returns
 * false (and leaves the module disabled) on any validation/setup
 * failure. */
bool api_blob_init(const char* root_dir, const char* prefix);

/* True iff blob is enabled and `path` starts with the configured
 * prefix. */
bool api_blob_path_matches(const char* path, size_t path_len);

/* Handles one request already known to match the blob prefix. */
void api_blob_dispatch(http_method_t method,
                       const char* path, size_t path_len,
                       const char* body, size_t body_len,
                       api_resp_t* resp);

#endif
