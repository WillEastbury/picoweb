#ifndef METAL_STATIC_PACK_H
#define METAL_STATIC_PACK_H

/* Serves static content directly from picowal cards instead of the
 * on-disk wwwroot tree. A configured (card, prefix) pair maps request
 * paths under the prefix straight onto picowal records:
 *
 *   GET {prefix}{record}[.ext]   -> raw bytes from card/{record}
 *   GET {prefix}                 -> record 0 (an "index" convention)
 *
 * {record} is a decimal integer (0..PICOWAL_RECORD_MAX). The optional
 * trailing extension is used only for MIME sniffing (mime.c); it is not
 * part of the picowal key. This lets an operator publish e.g.
 * "/site/0/index.html", "/site/0/app.js", "/site/0/style.css" out of
 * card 7's records 0/1/2 without touching the filesystem.
 *
 * Reuses the same open picowal_db_t handle as the /wal/ API
 * (api_picowal_db()) -- no second volume/file descriptor.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "http.h"
#include "api.h"

bool static_pack_enabled(void);

/* Configure once on the main thread, after api_picowal_init() has opened
 * the volume. prefix must start and end with '/'. Returns false (leaves
 * the module disabled) on any validation failure. */
bool static_pack_init(uint16_t card, const char* prefix);

bool static_pack_path_matches(const char* path, size_t path_len);

/* Handles one request already known to match the static-pack prefix.
 * GET/HEAD serve the record's raw bytes (see above). PUT/DELETE publish or
 * remove a record directly -- bypassing the /wal/ JSON-schema validation
 * pipeline entirely, since static content is arbitrary raw bytes (HTML,
 * bytecode, images, ...) not schema-validated JSON. PUT/DELETE always
 * require credentials (see api_require_pw_auth): the X-PW-Auth header +
 * session cookie when --oidc-cookie-auth is enabled, otherwise the
 * X-PW-Write-Token header matching --picowal-write-token. */
void static_pack_dispatch(http_method_t method,
                          const char* path, size_t path_len,
                          const char* body, size_t body_len,
                          const char* cookie, size_t cookie_len,
                          bool has_pw_auth_header,
                          const char* write_token, size_t write_token_len,
                          api_resp_t* resp);

#endif
