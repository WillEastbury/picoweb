#ifndef METAL_IDE_H
#define METAL_IDE_H

/* ide.c — hosted PicoScript IDE, served straight out of the picoweb
 * executable (compiled-in assets, no filesystem dependency at runtime).
 *
 * Enabled automatically whenever picowal is configured (--picowal-device),
 * under a configurable prefix (--ide-prefix, default "/ide/"):
 *
 *   GET  {prefix}                -> the ACTUAL upstream PicoScript WebIDE
 *                                    portal (vendored verbatim from
 *                                    ../picoscript/docs/index.html at build
 *                                    time -- Guide & Reference / WebIDE /
 *                                    Showcase nav, full Monaco editor,
 *                                    dialect tabs, Compile & Run/Step/
 *                                    Reset, disassembly/registers/watches),
 *                                    with tools/ide_server_bridge.js
 *                                    injected before </body> to wire it to
 *                                    THIS picoweb instance's live /wal/,
 *                                    PicoSTS and deploy endpoints, plus a
 *                                    first-class top-level "PicoWAL" nav
 *                                    tab that opens {prefix}picowal.html.
 *   GET  {prefix}picowal.html     -> the rebuilt PicoWAL workspace page
 *                                    (tools/ide_picowal_workspace.html),
 *                                    served as a separate compiled-in
 *                                    asset for CSS isolation (opened in an
 *                                    iframe from the portal's PicoWAL tab,
 *                                    or navigable directly). Full packs/
 *                                    schemas/cards/permissions/query/
 *                                    Fast Serial (BSO1) workspace against
 *                                    the real /wal/ API -- see README.
 *   GET  {prefix}pico_hooks.js    -> compiled-in PicoScript hook table JS
 *   GET  {prefix}picoc.js         -> compiled-in PicoScript compiler JS
 *                                    (PicoCompile.compile(src, lang))
 *   GET  {prefix}picovm.js        -> compiled-in PicoScript VM JS (PicoVM)
 *                                    (kept for backward compatibility --
 *                                    the vendored portal above inlines its
 *                                    own copy and no longer fetches these)
 *   GET  {prefix}baremetal-binary.js -> vendored BareMetal.Binary BSO1 codec
 *                                    JS (byte-for-byte from the sibling
 *                                    baremetaljstools repo, never modified),
 *                                    used by the PicoWAL workspace's "Fast
 *                                    Serial (BSO1)" panel to derive a wire
 *                                    schema from the rich PicoWAL field
 *                                    schema and serialize/deserialize
 *                                    signed BSO1 bytes for a card.
 *   GET  {prefix}config           -> JSON: PicoSTS issuer/client id/
 *                                    audience + the configured static/code/
 *                                    picowal route prefixes, so neither
 *                                    page needs its own copy of the CLI
 *                                    flags picoweb was started with.
 *   GET/HEAD/PUT/DELETE {prefix}card/{pack}/{record}
 *                                 -> authenticated raw-byte picowal CRUD
 *                                    (no schema validation, PICOWAL_DATA_MAX
 *                                    per record) used by the WebIDE bridge
 *                                    to save/load PicoScript source and by
 *                                    the PicoWAL workspace's Fast Serial
 *                                    (BSO1) panel. Always requires
 *                                    credentials (api_require_pw_auth).
 *
 * The card CRUD endpoint is partition-aware for all of GET/HEAD/PUT/DELETE
 * (tenant-scoped, same rendezvous-hashed ownership model as /wal/ and
 * static_pack): a node that isn't the current owner of a given (pack,
 * record) redirects or transparently proxies to the true owner, so reads
 * and writes work through any node in the cluster. */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "http.h"
#include "api.h"

bool ide_enabled(void);

/* Configure once on the main thread, after api_picowal_init() has opened
 * the volume (the card CRUD endpoint needs it; the compiled-in HTML/JS
 * assets don't). prefix must start and end with '/'. Returns false (leaves
 * the module disabled) on any validation failure. */
bool ide_init(const char* prefix);

bool ide_path_matches(const char* path, size_t path_len);

void ide_dispatch(http_method_t method,
                  const char* path, size_t path_len,
                  const char* body, size_t body_len,
                  const char* cookie, size_t cookie_len,
                  bool has_pw_auth_header,
                  const char* write_token, size_t write_token_len,
                  const char* tenant_id, size_t tenant_id_len,
                  bool is_partition_hop,
                  api_resp_t* resp);

#endif
