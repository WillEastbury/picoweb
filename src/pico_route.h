#ifndef METAL_PICO_ROUTE_H
#define METAL_PICO_ROUTE_H

/* Dynamic routes rendered by PicoScript bytecode loaded from picowal.
 *
 * A configured (card, prefix) pair mounts one PicoScript "router" program
 * per request under the prefix. The program itself is stored as raw
 * bytecode (little-endian uint32 words, as produced by
 * `picoscript_build.py emit --as bytecode`) in picowal record 0 of the
 * given card; it is fetched and re-verified on *every* request (no
 * caching across requests), so publishing new code is just a picowal
 * write to that record -- no server restart, no filesystem deploy.
 *
 * The program sees the request through the same Req.* / Resp.* host hooks
 * as PicoScript's native HTTP server (picovm.c): Req.Method()/Path()/
 * Header()/BodySpan(), Resp.Status()/Header()/Write()/End(). It typically
 * dispatches on Req.Path() itself (one router per prefix), mirroring the
 * PicoWAL host server's router.eng pattern.
 *
 * Storage.* / Search.* hooks (0x60-0x6F, 0x1A0-0x1A4, PV_CAP_STORAGE) are
 * bridged straight onto the *same* picowal volume used by /wal/: the
 * PicoScript register holding a numeric "pack" argument maps 1:1 onto a
 * picowal card, and "id" onto a picowal record, via picowal_db_pack_key.
 * This gives dynamic PicoScript routes read/write access to the exact
 * same data the /wal/ REST API and app-shell see.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "http.h"
#include "api.h"

bool pico_route_enabled(void);

/* Configure once on the main thread, after api_picowal_init() has opened
 * the volume. prefix must start and end with '/'. router_card holds the
 * bytecode program at record 0. Returns false on validation failure. */
bool pico_route_init(uint16_t router_card, const char* prefix);

bool pico_route_path_matches(const char* path, size_t path_len);

/* Handles one request already known to match the pico-route prefix.
 * Only a small, known set of headers is currently threaded through as
 * ctx->req_headers (Cookie); full arbitrary header passthrough would
 * require plumbing the raw header block out of server.c's request
 * parser, which only exposes specific pre-parsed fields today.
 *
 * PUT to the bare prefix (e.g. "PUT /app/") publishes new router bytecode
 * to record 0 of the code card, bypassing the /wal/ JSON-schema validation
 * pipeline (the payload is a raw bytecode blob, not JSON). Every other
 * method/path executes the current bytecode against the request. When
 * --oidc-cookie-auth is enabled, the PUT deploy path requires the same
 * X-PW-Auth header + session cookie that /wal/ mutations require (see
 * api_require_pw_auth); has_pw_auth_header carries that header's presence. */
void pico_route_dispatch(http_method_t method,
                         const char* path, size_t path_len,
                         const char* body, size_t body_len,
                         const char* cookie, size_t cookie_len,
                         bool has_pw_auth_header,
                         const char* write_token, size_t write_token_len,
                         api_resp_t* resp);

#endif
