# picoweb

A tiny, native-compiled, multi-core HTTP/1.1 static webserver in C — designed
around a single hot-path principle:

> **Take the calculation hit at startup. At runtime, do nothing but
> hash, lookup, and `sendmsg`.**

Every file in your `wwwroot/` is read into RAM once at boot. Each response
(headers + body) is pre-built into an immutable, mmap'd, `mprotect(PROT_READ)`
arena. Every URL is hashed once into a flat open-addressing table. At request
time picoweb parses the request line, hashes `(host, path)`, walks at most a
few cache-warm probes to a `resource_t*`, picks one of two pre-baked head
buffers (`Connection: keep-alive` or `Connection: close`) and calls
`sendmsg(MSG_NOSIGNAL)` of an `iovec` of pointers into the arena. **No
`malloc`, no `mmap`, no `realloc`, no `sprintf`, no `strlen`, no payload
copies on the request path.** Ever.

On a single core of a modest x86-64 box this delivers ~250k req/s for a small
file via `wrk -c 64`, and ~810k req/s aggregated across four worker threads
serving in parallel. It will saturate a 10 GbE link long before it saturates
the CPU.

> **Status:** working hobby project. The core static-file server (`src/`,
> excluding the `picowal` mini-datastore and the `userspace/` TLS/TCP/QUIC
> stack described below) is a few thousand lines of C; the repo as a
> whole (server + `userspace/` from-scratch TLS 1.3/TCP/QUIC/HTTP-3
> stack + `picowal` WAL datastore with replication) is ~44k lines
> across ~170 files. No external deps beyond libc + pthreads.
> Linux-only (uses `epoll`, `SO_REUSEPORT`, `accept4`). See
> `userspace/DESIGN.md` for the from-scratch network stack's current,
> honestly-tracked status (what's real/tested/wired into the live
> binary vs. sketched-but-not-wired).

---

## Table of contents

- [Why](#why)
- [Design highlights](#design-highlights)
- [Build](#build)
- [Run](#run)
- [Optional API backends](#optional-api-backends)
- [PicoSTS login provider](#picosts-login-provider-external-oidc-authority)
- [Hosted PicoScript IDE](#hosted-picoscript-ide-ide)
- [Filesystem conventions](#filesystem-conventions)
  - [Virtual hosts](#virtual-hosts)
  - [`_chrome/` — header/footer wrap for HTML](#_chrome--headerfooter-wrap-for-html)
  - [`_pages/` — opt-in chromed page tree](#_pages--opt-in-chromed-page-tree)
- [HTTP behaviour](#http-behaviour)
- [Built-in endpoints](#built-in-endpoints)
- [SIMD acceleration](#simd-acceleration)
- [Performance](#performance)
- [Limits / hard caps](#limits--hard-caps)
- [What's deliberately NOT supported](#whats-deliberately-not-supported)
- [Source layout](#source-layout)
- [Userspace TCP+TLS foundation](#userspace-tcptls-foundation-userspace)
- [License](#license)

---

## Why

Most static webservers spend the request path doing things that could have
been done at boot:

- formatting `Content-Length:` from an `int` into ASCII,
- recomputing `Content-Type:` from a file extension,
- reading the file from disk (or even the page cache),
- copying the body buffer through one or more userspace queues,
- parsing every request header you'll never look at.

picoweb does none of that. The cost of every static response is paid **once,
at startup**. The runtime is reduced to: hash, table probe, two- to four-entry
`iovec`, `sendmsg`. The send loop is a state machine over a per-connection
struct; partial sends and slow clients yield back to `epoll` rather than
blocking a worker.

It's a learning exercise in extracting the last few percent — flat tables for
cache locality, pre-baked headers, branchless lookup, vectorised
hostname-equality, per-worker zero-contention metrics — and a useful piece of
infrastructure if all you want is "serve this folder really, really fast".

---

## Design highlights

- **Zero allocation on the request path.** The resource arena is mmapped and
  `mprotect(PROT_READ)` after build. Connections are rented from / returned
  to a fixed-size per-worker pool. No `malloc` ever runs after `main()`
  finishes initialisation.
- **Pre-baked everything.** Both `Connection: keep-alive` and `Connection:
  close` head variants are built once per resource. `Content-Length` is
  baked into ASCII. `Content-Type` is baked in. Even canned errors (400,
  404, 405) are static `resource_t`s.
- **Flat `(host, path)` hash table.** A single open-addressing FNV-1a probe,
  with linear probing on collision. No three-tier walk, no pointer chasing.
  Each slot is 40 bytes, the table is sized to ~2× total entries (load
  factor 0.5).
- **One `epoll` loop per CPU core** via `SO_REUSEPORT`. Workers are
  independent; no shared mutable state on the hot path. Connection pool,
  read buffers, and metrics histograms are all per-worker.
- **Cache-line-aligned `resource_t`** (64 B, `__attribute__((aligned(64)))`)
  containing the two head pointers, the body pointer, body length, an
  optional pointer to a per-host header/footer "chrome" pair, and an
  optional pointer to a precomputed compressed variant. All eight pointers
  fit in one cache line.
- **Pre-compression with `picoweb-compress`.** Every text resource gets a
  separately-stored compressed copy (chrome + body baked into one stream)
  built at startup. Clients that send `Accept-Encoding: picoweb-compress`
  get the variant; everyone else gets identity. **No allocations and no
  CPU spent compressing anything on the hot path.** See *Performance
  flags* below.
- **Send path is a state machine.** Partial writes resume cleanly; slow
  readers are dropped via per-connection idle timeout. Keep-alive is bounded
  (default 100 reqs/conn, 10 s idle) so one bad client cannot hold a slot
  forever.
- **Optional `MSG_ZEROCOPY`** (5th positional arg). Opt-in per-server
  threshold; soft-fails on older kernels; drains the err queue on
  `EPOLLERR`. See *Performance flags*.
- **SIMD-accelerated string ops** (SSE2 on x86-64, NEON on aarch64, scalar
  fallback) for hostname lowercasing and 16-byte-chunked equality compare
  on the lookup key.
- **`/health` and `/stats` endpoints** with per-worker latency histogram and
  a background updater thread that rewrites the stats body in place once
  per second — **zero overhead on the hot path**, no atomics, no shared
  mutable state.

---

## Build

Linux only. `gcc` (or `clang`), `make`, libc, pthreads. No other
dependencies.

```sh
make            # release: -O3 -Wall -Wextra -Wshadow -Wpedantic
make debug      # ASan + UBSan + -O0 -g3
make clean
```

Produces a single statically-linked-against-libc binary called `picoweb`.

---

## Run

```sh
./picoweb                                # :8080, ./wwwroot, $(nproc) workers
./picoweb 8080 wwwroot 4                 # port, root, worker count
./picoweb 8080 wwwroot 4 100             # ...with max requests per keep-alive conn
./picoweb 8080 wwwroot 4 100 16384       # ...with MSG_ZEROCOPY for sends >= 16KB
./picoweb --help
```

Positional args:

| # | Name      | Default      | Notes |
|---|-----------|--------------|-------|
| 1 | PORT      | `8080`       |       |
| 2 | ROOT      | `./wwwroot`  | Directory containing per-host folders. |
| 3 | WORKERS   | `nproc`      | Independent epoll loops, `SO_REUSEPORT`. |
| 4 | MAX_REQS  | `0` = unlimited | Per keep-alive connection cap. |
| 5 | ZC_MIN    | `0` = off    | Bytes; opts in to MSG_ZEROCOPY for sends ≥ this size. See *Performance flags* below. |

Startup banner shows the SIMD path being used, the arena footprint, and
per-worker readiness:

```
metrics: 4 worker(s), tsc/sec=2693907772
  host 'localhost': _pages/ enabled (chromed virtual root)
picoweb: arena 86379 B for 2 host(s) / 4 dir(s) / 6 file(s) (+3 aliases) / 1132 body B / 32 slots
  host '_default': 1 file(s)
  host 'localhost': chrome hdr=150B ftr=66B
  host 'localhost': 5 file(s)
picoweb: 4 worker(s) on :8080, root=wwwroot, maxreqs=100, zerocopy=off, simd=x86-64 SSE2
```

Bind to a privileged port (80, 443) by either running as root, or granting the
binary the capability:

```sh
sudo setcap 'cap_net_bind_service=+ep' ./picoweb
./picoweb 80 wwwroot
```

`SIGINT` / `SIGTERM` cleanly stops all workers.

---

## Optional API backends

picoweb can expose two lightweight data APIs in the same binary:

- **JSON file API** (existing): `--api-root=DIR [--api-prefix=/api/]`
- **picowal raw-volume API** (new): `--picowal-device=PATH [--picowal-prefix=/wal/]`
- **OIDC cookie auth for picowal** (optional): `--oidc-cookie-auth --oidc-google-client-id=... --oidc-entra-client-id=... [--oidc-cookie-ttl-sec=900] [--oidc-entra-tenant=...]`
- **PicoSTS login provider** (optional, external OIDC authority): `--picosts-issuer=URL --picosts-cookie-key=KEY [--picosts-client-id=spa] [--picosts-audience=api]` (requires `--oidc-cookie-auth`; see "PicoSTS login provider" below)

`picowal` uses a directory-based write-ahead-log (WAL) + `base.dat`
transactional engine (see "Storage engine" below for the on-disk layout,
transactions, durability, and checkpointing) and maps keys as
`card`/`record` integers:

- `card`: `0..1023`
- `record`: `0..4194303`
- route shape: `/{prefix}{card}/{record}` (default `/wal/{card}/{record}`)
- query endpoint: `POST /wal/query` with picowal query text (`S:`, `F:`, `W:`) including joined pack references
- list endpoint: `GET /wal/list/{pack}` returns `{pack, records:[{record,data}], count}` for app-shell list views.
  When `--picowal-partition-nodes` is configured, this fans out to every node in the tenant's pool
  (ownership is per-record, so a full-pack listing has no single owner) and merges the results the
  same way `/wal/query` already does, de-duplicating records defensively by id; the merged response
  gains `partial`/`shards_ok`/`shards_total` fields if any shard was unreachable. An inbound
  `X-PW-Partition-Hop` request is served from the local shard only, to avoid fan-out loops.
- report endpoint: `POST /wal/report` (query DSL body, or JSON `{"query":"..."}`) returns wrapped report JSON
- dashboard endpoint: `POST /wal/dashboard` (multiple query panels separated by `---`; optional `T:` title per panel)
- schema endpoint: `/wal/schema/{pack}` (`PUT/GET/HEAD/DELETE`, `POST` create-only)
- metadata wrappers:
  - `/wal/metadata/name/{pack}` → pack 1
  - `/wal/metadata/schema/{pack}` → pack 2
  - `/wal/metadata/permissions/{pack}` → pack 3 (`GET/HEAD/PUT/DELETE`) — persists a
    picoscript-style RBAC/RLS **design** document `{roles:[...], permissions:[{role,pack,actions}],
    rowPolicies:[{pack,role,predicate}]}`. **This pack is reserved metadata, not an enforcement
    boundary**: picoweb stores and replicates it so the IDE's Permissions panel (and any other
    tooling) can design/document intended access control, but no request path currently checks it
    before allowing a read/write/query — see "Permissions pack (metadata pack 3) — design-time only"
    below. Unlike pack 1/2 writes (open by default when neither `--oidc-cookie-auth` nor
    `--picowal-write-token` is configured), pack 3 mutations always require credentials via the same
    `api_require_pw_auth()` gate as `/ide/card/`/static/code raw writes.
  - `/wal/metadata/{pack}` → combined fetch (`pack1` + `pack2` + `pack3`, with `pack3`'s value
    also mirrored under a `permissions` key for discoverability)
- metadata cluster replication: when `--picowal-partition-nodes` is configured, every
  `PUT`/`DELETE` against `/wal/metadata/name|schema|permissions/{pack}` (packs 1/2/3) is
  replicated to **every** node in the tenant's pool, not just applied locally — metadata is
  expected to read identically from any node, unlike per-record data (which is sharded by
  ownership; see "Virtual-partition ownership routing" below). If a peer can't be reached or
  rejects the mutation, the response is `502 Bad Gateway` describing how many peers failed
  rather than silently reporting success while nodes have drifted apart. An inbound
  `X-PW-Partition-Hop` request (i.e. this node is itself the replication target of another
  node's fan-out) applies the mutation locally only, to avoid replication loops.
- metadata-derived form spec:
  - `/wal/forms/{pack}` (`GET/HEAD`) → returns a minimal JS handoff payload: `{pack, entity, schema, app}` where `schema` is pack 2 metadata as-is and `app` is expanded model metadata
  - example browser client: `/forms.html` (builds controls client-side from `schema` and submits to `/wal/{pack}[/{record}]`)
  - generated app shell: `/app.html` (metadata-driven `list/create/edit/detail` routes using browser hash navigation)
    - includes client-side filtering, sorting, pagination, and relation browse links derived from `joins`
    - includes host+pack local versioned config persistence (save/load/history) via browser `localStorage`
    - includes report and dashboard builders that call `/wal/report` and `/wal/dashboard`
    - includes browser auth wiring (`login/logout` + cookie credentials + `X-PW-Auth`)
    - includes client-side schema validation parity for required/type/email/regex/transition/lookup checks
  - expanded app metadata model is carried in the same response under `app` (v1), with string-config keys:
    - `title`, `icon`, `pages`, `nav`, `list_columns`, `layout`, `actions`, `page_size`, `default_sort`
    - `field_labels` and `field_placeholders` (`field=value;...`)
- auth endpoints (when `--oidc-cookie-auth` is enabled):
  - `POST /wal/auth/login` body: `{"provider":"google|entra|picosts","access_token":"..."}`
    validates the token with the named provider, then sets a short-lived `HttpOnly` `Path=/` cookie
    (covers `/wal/`, `/site/`, `/app/`, `/ide/` alike). `google`/`entra` sessions are tracked in a
    node-local table; `picosts` sessions are stateless (HMAC-signed, no server-side table --
    see "PicoSTS login provider" below), which is what makes them cluster-safe.
  - `GET /wal/auth/me` returns `{"principal":"<sub>"}` for the current session, or `401`
  - `POST /wal/auth/logout` clears the cookie (best-effort server-side revoke for
    table-backed sessions; stateless `picosts` sessions only support client-side clearing)
  - all other `/wal/*` routes require `X-PW-Auth: 1` and a valid cookie
- CORS is enabled on API responses when an `Origin` header is present:
  - preflight `OPTIONS` for `/api/*` and `/wal/*` returns `204`
  - response headers include `Access-Control-Allow-Origin`, methods, headers, and credentials
- Minimal tenant/env routing context plumbing for deployments behind an
  auth-terminating Ingress/oauth2-proxy:
  - principal id is resolved from `pw_session` cookie (falls back to `anonymous` when absent/invalid)
  - trusted upstream identity headers override that context when present:
    `X-PW-Principal`, `X-Principal-Id`, `X-Auth-Request-User`,
    `X-Auth-Request-Preferred-Username`, `X-Auth-Request-Email`,
    `X-Forwarded-User`, or `X-Forwarded-Email`
  - only trust these headers when your Ingress strips any client-supplied
    copies before forwarding to picoweb
  - tenant context is resolved from the `Host` header:
    - first `.` component => `tenant_id`
    - second `.` component => `tenant_system` (`dev|qa|prod`)
  - API responses include:
    - `X-PW-Principal-Id`
    - `X-PW-Tenant-Id`
    - `X-PW-Tenant-System`

picowal mutation validation (`PUT/POST/DELETE` for non-system packs) is schema-driven
from pack 2 metadata and enforces:

- lookup referential integrity (`joins`: `<targetPack>=<fk_field>` CSV)
- required fields (`required`: CSV)
- nullable fields (`nullable`: CSV — also settable per-field via a trailing `?` on the
  field's `types` entry, e.g. `email=string?`; either form allows a JSON `null` even if
  the field is also `required`)
- read-only fields (`readonly`: CSV — a `PUT` to an *existing* record may not change the
  value of a field listed here; `409` if it tries. New records via `POST`, or a `PUT`
  creating a not-yet-existing record, are unaffected)
- max length (`max_lengths`: `field=N;...` — a character-count cap for string-kind
  fields, or an element-count cap for `array_u16` fields)
- type checks (`types`: `field=type;...`). Supported `type` values:
  - primitives (unchanged): `string`, `number`, `integer`, `bool`/`boolean`, `object`, `array`
  - rich logical types: `uint8`/`uint16`/`uint32`/`int8`/`int16`/`int32` (range-checked
    whole integers), `decimal` (any JSON number), `ascii` (string, all bytes ≤ 0x7F),
    `utf8` (string, any), `date` (`YYYY-MM-DD`), `time` (`HH:MM` or `HH:MM:SS`),
    `datetime` (`YYYY-MM-DDTHH:MM:SS`, `T` or space separator), `array_u16` (JSON array
    of integers `0..65535`), `blob` (a base64 string, or a JSON array of integers
    `0..255`), `lookup` (a non-negative integer record id — pair with a `joins` entry for
    it to also be checked against the target pack's existing records)
  - any of the above accepts a trailing `?` (e.g. `qty=uint16?`) to allow `null`
- email checks (`email`: CSV field list)
- regex checks (`regex`: `field=pattern;...`)
- transition rules (`transitions`: `field=from>to|from2>to2;...`)

Pack-level and per-field **design metadata** that the server stores and returns
unchanged but does not itself validate or enforce (consumed by the IDE's Packs & Schemas
field builder and typed Cards editor): `module` (string, groups packs in the pack
navigator), `public_read` (bool, a documentation-only visibility flag), `children` (CSV
of child pack ids, used to render master-child grids), `list_columns` (CSV), `ordinals`
(`field=N;...`, display order), `lookup_labels` (`field=displayField;...`, which field of
the lookup target pack to show), `field_labels`/`field_placeholders`
(`field=value;...`, pretty label/input placeholder — pre-existing keys also used by the
`/wal/forms/{pack}` GUI form spec).

### Permissions pack (metadata pack 3) — design-time only, not an enforcement boundary

`/wal/metadata/permissions/{pack}` stores a document shaped like:

```json
{
  "roles": ["admin", "viewer"],
  "permissions": [{"role": "viewer", "pack": 12, "actions": ["read"]}],
  "rowPolicies": [{"pack": 12, "role": "viewer", "predicate": "status|==|Placed"}],
  "assignments": [{"principal": "user@example.com", "roles": ["viewer"]}]
}
```

`assignments` (`[{principal, roles:[...]}]`) maps a PicoSTS subject to the role(s) above,
so operators can document/track which principals are intended to hold which roles. Like
the rest of this document, it is stored and cluster-replicated verbatim but **not read by
picoweb to authorize anything**.

This is the same `{roles, permissions, rowPolicies}` RBAC/RLS design model already used by the
picoscript WebIDE's RBAC designer (`rowPolicies` predicates use the same `field|op|value` syntax
as the query `W:` clause). **picoweb persists and cluster-replicates this document, but does not
currently enforce it**: no `/wal/`, `/ide/`, `/site/`, or `/app/` request path consults pack 3
before allowing a read, write, delete, or query. Treat it as documentation of intended access
control captured alongside the schema (useful for code review, downstream authorization services,
or a future enforcement layer), not as an actual security control — reads/writes are gated only by
the mechanisms described above (`--oidc-cookie-auth` cookies or `--picowal-write-token`, both
independent of anything stored in pack 3).

Query language (multi-line body):

```text
S:name,13.city
F:12,13
W:13.country|==|UK
```

- `S:` select list (`pack.field` supported)
- `F:` from packs (numeric card ids, first is primary)
- `W:` predicates (`==`, `!=`, `>`, `<`, `>=`, `<=`, `IN`, `NI`)

Conventions wired in:
- **pack 0** = users (query access denied)
- **pack 1** = pack-name registry
- **pack 2** = schema store (`fields` / `joins`)

Example:

```sh
./picoweb --picowal-device=/var/lib/picowal --picowal-format \
          --picowal-bytes=1073741824 --picowal-prefix=/wal/ \
          8080 wwwroot
```

Safety knobs:

- `--picowal-device=DIR` is a **directory**, not a raw block device or single
  file — it holds `base.dat` plus one or more `wal-NNNNNNNN.wal` segment files
- `--picowal-format` is required to initialize a new (empty) volume directory
- default WAL segment size is **1 GiB** (`--picowal-bytes`); segments seal and
  rotate to a new file once full
- writes are durable (`fdatasync`) at the configured durability tier before ack
- when OIDC auth is enabled, session cookies are short-lived (`Max-Age` = `--oidc-cookie-ttl-sec`, default 900s)

---

## Storage engine: WAL segments, `base.dat`, transactions, durability

picowal's engine keeps two kinds of files inside the device directory:

- **`base.dat`** — a compacted, checkpointed snapshot of all live keys, laid
  out as fixed-size sector-aligned slots addressed by `card`/`record`.
- **`wal-NNNNNNNN.wal` segments** — an ordered sequence of append-only,
  crash-safe log files. New writes always go to the *leading* (currently
  open) segment; once a segment reaches `--picowal-bytes`, it is **sealed**
  (marked read-only, never appended to again) and a new leading segment is
  created. Sealed segments accumulate until a checkpoint folds them into
  `base.dat` and deletes them.

**Crash safety / A/B superblock.** Each file (both `base.dat` and every WAL
segment) begins with two alternating 512-byte superblock slots, each carrying
a monotonically increasing generation counter and a checksum. A checkpoint
or append writes to whichever slot is *not* currently active; on reopen,
whichever slot has a valid checksum **and** the higher generation wins. A
torn/half-written superblock from a mid-write crash just fails its own
checksum and is ignored in favor of the other, still-intact slot — the
engine can never boot from a corrupt header, and at most the last
in-flight append is lost (not the whole file).

**Transactions.** Every mutation happens inside a transaction:

- a single implicit call (`picowal_db_put_key`/`picowal_db_delete_key`) opens,
  performs one change, and commits immediately — this is what the `/wal/*`
  HTTP routes use today;
- `picowal_db_txn_begin()` / `..._txn_put()` / `..._txn_delete()` /
  `..._txn_commit()` / `..._txn_abort()` let a caller batch several changes
  into one atomic, single commit-record unit (not yet exposed over HTTP —
  internal-API only for now).

**Durability tiers** (`picowal_durability_t`, chosen per-commit):

| Tier | Behavior |
|---|---|
| `PICOWAL_DURABILITY_IMMEDIATE` | returns as soon as the record is queued in memory — fastest, weakest guarantee |
| `PICOWAL_DURABILITY_LOCAL` | returns only after `fdatasync` on the local WAL segment — survives a local crash/power loss (this is what `/wal/*` HTTP routes use) |
| `PICOWAL_DURABILITY_REMOTE` | returns only once at least one replica has acknowledged the commit over `/repl/ack/{id}/{off}` — survives loss of the primary node itself |

**Checkpointing.** A background thread on the primary periodically checks how
many bytes are reclaimable (bytes in sealed WAL segments that are already
superseded/compacted into `base.dat`-eligible state); once that exceeds a
threshold it folds the sealed segments into `base.dat` and deletes the
now-redundant `wal-*.wal` files, keeping the device directory bounded in size
instead of growing forever. This replaces the earlier single-file design's
periodic superblock-only checkpoint with genuine log truncation.

---

## Static content and dynamic routes straight from picowal

Two more optional route types serve content directly out of a picowal card,
bypassing the on-disk `wwwroot` tree and the `/wal/` JSON-schema pipeline
entirely (both operate on raw bytes):

- **static content**: `--picowal-static-card=N [--picowal-static-prefix=/site/]`
  - `GET/HEAD /{prefix}{record}[.ext]` and `GET/HEAD /{prefix}{record}/{filename.ext}`
    both return the raw bytes stored at `(card, record)`; an omitted record
    segment means record `0`. The optional extension drives `Content-Type`
    via MIME sniffing (falls back to `application/octet-stream`) and is
    taken from the trailing filename's last `.` when present (e.g.
    `/site/0/index.html` and `/site/0.html` both serve record `0` as
    `text/html`) -- the filename is never part of the picowal key, only
    used for MIME, so this is how a small multi-file bundle (`index.html`
    at record 0, `app.js` at record 1, ...) gets human-readable URLs
    without touching the filesystem.
  - `PUT /{prefix}{record}[.ext]` writes the request body verbatim to
    `(card, record)` — no JSON validation, any byte content is accepted
  - `DELETE /{prefix}{record}[.ext]` removes the record (`404` if absent)
  - partition-aware for all of GET/HEAD/PUT/DELETE when
    `--picowal-partition-nodes` is configured (see "Virtual-partition
    ownership routing" below): a node that doesn't own a given record's
    virtual partition redirects or transparently proxies to the true
    owner, so static content is reachable through any node in the pool
- **dynamic PicoScript routes**: `--picowal-code-card=N [--picowal-code-prefix=/app/]`
  - the code card's record `0` holds a compiled PicoScript bytecode program
    (see `picoscript_build.py emit --as bytecode --hex`, then pack the hex
    words little-endian into a raw binary — there is no raw-binary emit
    mode yet)
  - `GET/HEAD/POST/... /{prefix}...` (any method except the bare-prefix
    `PUT` below) re-fetches, re-verifies (`pv_verify`), and executes the
    bytecode against the request on every call — no restart needed to pick
    up newly deployed code; the program controls its own routing via
    `Req.Path()`/`Req.Method()` and reads/writes storage via `Storage.*`
    hooks bridged to the configured picowal volume
  - `PUT /{prefix}` (bare prefix, no trailing path segment) deploys new
    bytecode: the raw body is verified with `pv_verify` before being
    written to record `0`; malformed bytecode is rejected with `400`
    instead of being persisted

Both PUT/DELETE write paths always require credentials — there is no
unauthenticated default here, unlike the rest of picoweb's non-`/wal/`
surface:

- when `--oidc-cookie-auth` is enabled, the same `X-PW-Auth: 1` header +
  valid session cookie that `/wal/` mutations require applies;
- otherwise, a shared secret configured via `--picowal-write-token=TOK`
  (or the `PICOWAL_WRITE_TOKEN` environment variable) must be presented in
  the `X-PW-Write-Token` header, compared with a constant-time check;
- if neither OIDC auth nor a write token is configured, these routes
  refuse all writes with `503 Service Unavailable` rather than defaulting
  open — a startup warning is logged in that case.

Example:

```sh
./picoweb --picowal-device=/var/lib/picowal --picowal-format \
          --picowal-bytes=1073741824 \
          --picowal-static-card=5 --picowal-static-prefix=/site/ \
          --picowal-code-card=6 --picowal-code-prefix=/app/ \
          --picowal-write-token=change-me-to-a-real-secret \
          8080 wwwroot
```

---

## PicoSTS login provider (external OIDC authority)

picoweb treats [PicoSTS](../developercli/sts/README.md) (or any compatible
OIDC authority) purely as an **identity authority** — picoweb never issues
tokens, never talks to `/token` itself, and does not port any of PicoSTS's
own service logic into this repo. The browser does the Authorization Code +
PKCE dance directly against PicoSTS; picoweb's job is to validate the
resulting access token and turn it into its own session cookie:

```sh
./picoweb --picowal-device=/var/lib/picowal --picowal-format \
          --oidc-cookie-auth --oidc-cookie-ttl-sec=900 \
          --picosts-issuer=https://sts.example.com \
          --picosts-client-id=spa --picosts-audience=api \
          --picosts-cookie-key="$(openssl rand -hex 32)" \
          --ide-prefix=/ide/ \
          8080 wwwroot
```

- `--picosts-issuer=URL` (required to enable the provider) — PicoSTS's
  issuer/authority URL, trimmed of any trailing `/`
- `--picosts-client-id=ID` — SPA client id registered with PicoSTS (default `spa`)
- `--picosts-audience=AUD` — expected access-token `aud` claim (default `api`)
- `--picosts-cookie-key=KEY` (or `PICOSTS_COOKIE_KEY` env var; required) —
  HMAC-SHA256 key signing the stateless session cookie described below

Login flow (`POST {picowal-prefix}auth/login` with
`{"provider":"picosts","access_token":"..."}`, same endpoint google/entra use):

1. `GET {issuer}/userinfo` with `Authorization: Bearer <token>` must
   succeed and return a `sub` claim.
2. The token is independently decoded as a JWT (payload only — this never
   verifies the JWT signature, matching the "validate through userinfo +
   payload checks" contract; PicoSTS's signing key/JWKS aren't consumed
   here): its `iss` must match `--picosts-issuer`, `aud` must match
   `--picosts-audience`, `exp`/`nbf` must be valid for the current time,
   and `sub` must agree with the userinfo `sub`.
3. On success, picoweb issues a **stateless** `pw_session` cookie: `v1.` +
   base64url(`exp|sub`) + `.` + hex(HMAC-SHA256 over the tag+payload,
   keyed by `--picosts-cookie-key`), using the constant-time compare
   already used elsewhere in this codebase for MAC checks. There is no
   node-local session table entry for `picosts` logins — any node in a
   cluster configured with the **same** `--picosts-cookie-key` can
   independently verify the cookie and recover the subject, which is what
   makes `/ide/`, `/site/`, `/app/` and `/wal/` all work correctly behind
   a load balancer that doesn't pin a client to one node. `google`/`entra`
   logins keep using the pre-existing node-local session table.

`GET {picowal-prefix}auth/me` returns `{"principal":"<sub>"}` for the
current session (`401` if absent/invalid/expired) — used by the IDE (and
any other SPA) to discover who's signed in.

---

## Hosted PicoScript IDE (`/ide/`)

Whenever `--picowal-device` is configured, picoweb also serves the
**actual, upstream PicoScript WebIDE portal** — not a hand-rolled
substitute — compiled straight into the executable with no filesystem
dependency at runtime, under `--ide-prefix` (default `/ide/`):

- `GET /ide/` — the real portal vendored verbatim from the sibling
  `picoscript` repo's generated `docs/index.html` (built by that repo's
  own `gen_site.py`): the full **Guide & Reference / Code Editor /
  Showcase** navigation (the hosted bridge relabels upstream `WebIDE` to
  **Code Editor** and opens it by default), file sidebar
  (New/Open/Save/Save as/Rename/Delete/Package/
  Schema/Event/Ontology/RBAC-RLS designers), [Monaco](https://microsoft.github.io/monaco-editor/)
  editor (falls back to a plain `<textarea>` if Monaco fails to load —
  network blocked, CSP, slow CDN — a timeout guards this, not just script
  `onerror`), dialect tabs (C/BASIC/Python/English/COBOL/Report/Workflow),
  **Compile & Run** / **Compile & Step** / **Step** / **Reset**, and the
  debug tabs (Disassembly/Registers/Watches/Output). `tools/gen_ide_assets.py`
  injects `tools/ide_server_bridge.js` right before `</body>` at
  build-generation time — the vendored HTML/CSS/JS above it is never
  hand-edited, so re-running `../picoscript/gen_site.py` and regenerating
  always drops in cleanly (see "Regenerating IDE assets" below).
- `GET /ide/picowal.html` — the rebuilt **PicoWAL workspace** (its own
  compiled-in asset, for CSS isolation), shown as a full-width portal tab
  from the top-level **PicoWAL** control via a same-origin `<iframe>`.
  The portal topbar remains visible and owns the only login/logout controls;
  `?embedded=1` removes duplicate workspace chrome. See
  "PicoWAL workspace" below.
- `GET /ide/pico_hooks.js`, `/ide/picoc.js`, `/ide/picovm.js` — the
  PicoScript compiler/runtime JS (`PicoCompile.compile(src, lang)` /
  `PicoVM`), served from compiled-in byte arrays generated from the
  sibling `picoscript` repo's `vm/*.js` (see "Regenerating IDE assets"
  below). Kept for backward compatibility with any external tooling that
  fetches them directly — the vendored portal above inlines its own copy
  of the compiler/VM and no longer requests these itself.
- `GET /ide/config` — JSON `{ide_prefix, wal_prefix, static_prefix,
  code_prefix, picosts_enabled, picosts_issuer, picosts_client_id,
  picosts_audience}` so neither page ever needs its own copy of the CLI
  flags picoweb was started with.
- `GET/HEAD/PUT/DELETE /ide/card/{pack}/{record}` — authenticated raw-byte
  picowal CRUD (no schema validation, `PICOWAL_DATA_MAX` per record;
  `pack` 0..1023, `record` 0..4194303) used by the bridge to save/load
  PicoScript source and by the PicoWAL workspace's Fast Serial (BSO1)
  panel. **Every** method (including reads) requires credentials via the
  same `api_require_pw_auth` gate as static-pack/pico-route writes
  (`X-PW-Auth: 1` + session cookie when `--oidc-cookie-auth` is enabled,
  otherwise `X-PW-Write-Token`). Partition-aware for all of
  GET/HEAD/PUT/DELETE, same as static content.

### The server bridge (`tools/ide_server_bridge.js`)

This is the *only* place that wires the vendored, upstream WebIDE to a
running picoweb instance — everything else in the portal is untouched
upstream code:

- Fetches `/ide/config` on load and points the WebIDE's own "live server"
  concept (`liveServerUrl()`/`liveServerSet()`, upstream concepts already
  used by the Cards/Query/Schema panels) at this instance's same-origin
  `config.wal_prefix` (default `/wal`) — **hosted mode is live by
  default**, not the upstream localStorage simulator. An explicit
  "offline simulator" checkbox next to the existing live-server status bar
  is the only way back to the simulator (`liveServerSet("")`), persisted
  in `localStorage` across reloads.
- Overrides the upstream `liveFetch(path, opts)` so every live-mode
  request — `/list/{pack}`, `/{pack}`, `/schema/{pack}`, which resolve to
  `/wal/list/{pack}`, `/wal/{pack}`, `/wal/schema/{pack}` once the live
  server is `/wal` — carries `credentials:"include"`, `X-PW-Auth: 1`, and
  a JSON/text `Content-Type` default, matching the auth contract every
  other picoweb write path already uses.
- Replaces `schemaPushLive()` so pushing a `schemas/<pack>.schema.json`
  file to the live server translates the WebIDE's simple
  `{fields:[{name,type,...}]}` model into `picowal_validate.c`'s
  server-native CSV/assignment-map shape (`fields`/`required`/`nullable`/
  `readonly`/`email` as CSV; `types`/`max_lengths`/`regex`/`transitions`/
  `lookup_labels` as `field=value;...` assignments; `joins` as
  `targetPack=fkField,...`) instead of sending the WebIDE's own shape
  verbatim — `PicoWebBridge.transformSchemaToServerNative()` is exposed
  for testing/inspection and preserves any rich per-field metadata
  (`required`/`nullable`/`readonly`/`maxLength`/`email`/`regex`/`join`/
  `transitions`) a hand-edited `{ } JSON` schema might already carry.
- Adds a compact PicoSTS login/logout/status control into the portal's
  existing topbar (Authorization Code + PKCE, reusing `/wal/auth/login`,
  `/wal/auth/me`, `/wal/auth/logout` — see "PicoSTS" above) without
  altering the portal's own layout.
- Adds **Save Source** / **Load Source** (authenticated
  `{ide_prefix}card/{pack}/{record}`), **Deploy Bytecode** (`PUT` the last
  `Compile`d bytecode to `--picowal-code-prefix`) and **Publish Static**
  (`PUT` the active static file to `--picowal-static-prefix`) buttons into
  the WebIDE's existing Compile & Run/Step/Reset controls row, matching
  its `act`/`ghost` button styling and reporting status through the
  existing file-sidebar status line (`filesStatus()`).
- Adds a first-class **PicoWAL** tab next to Guide & Reference / WebIDE /
  Showcase. It opens `{ide_prefix}picowal.html?embedded=1` as a full portal
  view, with the same topbar and authentication state as the editor. The
  iframe isolates CSS only; it shares the same cookie and receives the
  portal's authenticated principal via same-origin `postMessage`.
- Points the (not locally vendored) Showcase tab at the real hosted
  `https://willeastbury.github.io/picoscript/showcase.html` instead of a
  dead relative link, since only `docs/index.html` itself is vendored.

### PicoWAL workspace (`GET /ide/picowal.html`)

A dedicated, visually-isolated page, normally embedded as the portal's
full PicoWAL tab — modeled on the real PicoWAL client's
navy/coral panel language (`picowal/client/js/index.html` + `picowal.js`),
not a dense flat admin form — giving a full front end for the real
picowal storage backend. Everything in it talks to the actual `/wal/` API
(`config.wal_prefix`), never `localStorage`/browser emulation. Left-hand
navigation (workspace switcher + a module-grouped "known packs" list from
metadata pack 1) and a right-hand main panel per section:

- **Packs & Schemas** — numeric pack id (`0..1023`) plus a name field
  (`/wal/metadata/name/{pack}`) and a rich visual field builder (ordinal,
  name, logical type, max length, required/nullable/read-only, and, for
  `lookup` fields, a target pack + display field) for the schema
  (`/wal/metadata/schema/{pack}`). Logical types: `bool`, `uint8/16/32`,
  `int8/16/32`, `number`, `decimal`, `ascii`, `utf8`, `date`, `time`,
  `datetime`, `array_u16`, `blob`, `lookup`, `object`, `array` — all
  enforced server-side by the extended `picowal_validate.c` (see below).
  Pack-level metadata: `module` (groups packs in the pack navigator),
  `public_read` (a design/documentation flag only — **not enforced**),
  `children` (CSV of child pack ids, used to render master-child grids),
  and `list_columns`. The builder writes the server-native shape directly:
  `fields`/`required`/`nullable`/`readonly`/`children` as CSV; `types`/
  `max_lengths`/`lookup_labels`/`field_labels`/`field_placeholders`/
  `ordinals` as `field=value;...` assignments; `joins` as
  `targetPack=fkField,...` (a lookup field's target pack is whichever join
  entry's `fkField` matches its name) — and preserves any other top-level
  schema keys (`title`, `regex`, `email`, `transitions`, `pages`, `nav`,
  `layout`, `actions`, `page_size`, `default_sort`, ...) untouched when
  loading and re-saving. A raw-JSON view/edit toggle is available
  alongside the builder for anything it doesn't have a widget for.
  "Known packs" lists every pack registered in metadata pack 1 (real
  cards, via `GET /wal/list/1`) with a Load shortcut.
- **Cards** — a schema-driven typed card editor (fetches
  `GET /wal/schema/{pack}` to render the right input per field: number
  inputs with range hints for `uintN`/`intN`, `date`/`time`/
  `datetime-local` pickers, a checkbox-ish select for `bool`, comma-list
  input for `array_u16`, and for `lookup` fields either a `<select>`
  (target pack has ≤16 records) or a searchable `<datalist>`-backed input
  (more than 16), showing the configured `lookup_labels` display field but
  storing the numeric record id) alongside a raw-JSON toggle. Dirty
  fields are tracked and shown next to the loaded `_version` (if the
  schema uses one); saving re-reads the record first and warns — but does
  not silently block — if the server-side version has moved since it was
  loaded (a client-side optimistic-concurrency check, not a real
  compare-and-swap: the durable operation is still a full `PUT`). Below
  the editor: a paginated (10/page), client-side-searchable list plus an
  MGET panel that fetches a comma-separated list of record ids
  concurrently; and, when the pack's schema declares `children`,
  master-child grids for each child pack (found by matching the child's
  own `joins` back to this pack) with add/edit/delete rows and a
  "Save All" that issues sequential authenticated writes and reports
  partial failures per row — **not** an atomic batch. All of this still
  goes through the real `/wal/{pack}/{record}` API (not `/ide/card/`), so
  pack 2 schema validation applies exactly as it would for any other
  client.
- **Permissions** — a visual editor for the pack-3 RBAC/RLS design
  document described above (add/remove roles, permission rows
  `role`/`pack`/`actions`, row-policy rows `role`/`pack`/`predicate`, and
  a principal → role `assignments` list — `[{principal,roles:[...]}]` —
  for documenting which PicoSTS subjects are meant to hold which roles),
  plus a raw-JSON toggle, backed by `/wal/metadata/permissions/{pack}`.
  The panel repeats the same caveat as the README: **this is
  design/deployment metadata, not an enforced authorization boundary** —
  `assignments` in particular is pure documentation; picoweb never reads
  it to authorize anything.
- **Query** — a visual S/F/W builder (select fields, including
  `pack.field` for joins; up to 4 FROM packs; WHERE rows with
  `== != > < >= <= IN NI`) that syncs to a DSL editor posted straight to
  `POST /wal/query` (the same cluster fan-out gateway described below),
  rendering the full JSON response plus a best-effort table view and the
  `count`/`partial`/`shards_ok`/`shards_total` fields when partitioning is
  enabled. An optional aggregate panel (SUM/AVG/MIN/MAX/COUNT/FIRST, with
  an optional GROUP BY field) is computed **entirely in the browser**
  over the rows the ordinary (non-aggregate) query already returned and
  is clearly labelled "client-aggregated" in the UI — `picowal_query.c`'s
  parser has no native aggregate support, so this is not a server
  capability and does not scale beyond whatever `PWQ_MAX_RESULTS`/scan
  limits the plain query already has.
- **Fast Serial (BSO1)** — a parallel **raw binary** card path, entirely
  separate from the JSON `/wal/` engine above. It vendors
  [BareMetal.Binary.js](../baremetaljstools/src/BareMetal.Binary.js)
  byte-for-byte as a compiled-in asset (`GET /ide/baremetal-binary.js`,
  see "Regenerating IDE assets" below) to derive a BSO1 wire schema from
  a pack's rich field schema (logical types map onto BareMetal.Binary's
  `Bool`/`Byte`/`UInt16`/`Int32`/`Decimal`/`String`/`DateOnly`/`TimeOnly`/
  `DateTime` wire types; `array_u16`/`blob`/`object`/`array`, which
  BareMetal.Binary has no native wire type for, are carried as their JSON
  text/CSV representation), accepts a user-supplied base64 HMAC-SHA256
  signing key (kept only in this page's in-memory JS state for the
  session — **never** written to `localStorage`/`sessionStorage`/cookies),
  serializes/deserializes the JSON currently in the Cards tab's editor,
  shows a byte-size and hex preview, and saves/loads the signed BSO1
  bytes through the same authenticated, partition-aware
  `{ide_prefix}card/{pack}/{record}` endpoint used for PicoScript
  source/static-bundle drafts. This is a genuine second on-disk card
  format sharing the same picowal key space (pack/record) as the JSON
  engine, has none of `picowal_validate.c`'s schema/type/lookup
  enforcement of its own, and is **not queryable** by `/wal/query` (which
  only understands the JSON card format) — pick a `(pack, record)` that
  isn't also used for a JSON card in the same deployment unless you
  intend to overwrite one format with the other.

### Parity with the embedded RP23xxB PicoWAL GUI

This IDE targets **feature parity on picoweb's own JSON-based clustered
card store**, not byte-for-byte route/wire parity with the RP23xxB
firmware's `web_server.c` (which uses a `0xCA7D`-tagged binary card
format, ordinal-numbered fields, and server-side-rendered pages). Rough
mapping:

| RP23xxB GUI (`picowal/src/httpd/web_server.c`) | picoweb hosted IDE | Notes |
|---|---|---|
| `/pack/{n}` paginated list + search | Cards tab list: client-side search + 10/page pager | Same 10/page convention; search/paging done in the browser over `GET /wal/list/{pack}`, not a server-side query |
| `/pack/{n}/{card}` typed SSR editor | Cards tab visual/raw typed editor | Same logical-type palette (`bool`/`uintN`/`intN`/`decimal`/`ascii`/`utf8`/`date`/`time`/`datetime`/`array_u16`/`blob`/`lookup`/`object`/`array`), client-rendered from JSON schema instead of server-rendered HTML |
| Lookup ≤16 → `<select>`, >16 → search input | Same ≤16/>16 threshold (`PW_LOOKUP_DROPDOWN_MAX`) | dropdown vs. `<datalist>`-backed search input |
| Master-child grids (schema ord `6` children + child lookup back-reference) | Child grids under a loaded card, from schema `children` (CSV) + child `joins` | Add/edit/delete rows + "Save All"; **sequential** authenticated writes, reported per-row — not an atomic batch like a single firmware write transaction |
| `/admin/meta/{n}` schema editor | Packs & Schemas tab field builder | Richer per-field metadata (ordinal/max length/nullable/read-only/lookup target+label) written as the JSON schema's CSV/assignment strings, not binary ordinal field defs |
| `/query` DSL + results | Query tab: visual S/F/W builder + DSL editor + results table | Adds a client-side aggregate layer (SUM/AVG/MIN/MAX/COUNT/FIRST, optional GROUP BY) since `picowal_query.c` has no native aggregate support — explicitly labelled "client-aggregated" |
| `0xCA7D` binary card + dirty-delta `PUT` (`picowal.js`) | Fast Serial (BSO1) tab | Uses BareMetal.Binary's BSO1 format (a *different* signed binary envelope) over `{ide_prefix}card/`, not the firmware's `0xCA7D` format, and is a full-record `serialize`/`deserialize` round trip rather than a per-field dirty delta |
| `/admin` user management | *(not implemented)* | Out of scope — picoweb's principal model is PicoSTS-issued tokens, not a local user table |
| Server-enforced RBAC/RLS | Permissions tab (design metadata only) | Documented, never enforced — see the in-app warning banner |

**Honest remaining gaps** (also called out in-app):

- **No server-side aggregate query support.** The Query tab's aggregate
  panel is computed client-side over whatever rows the plain query
  already returned; it is not a scalable server capability and doesn't
  benefit from cluster fan-out the way a native aggregate would.
- **No true dirty-delta PUT.** Unlike `picowal.js`'s `buildDelta()`
  (encodes and sends only changed fields), the IDE's Cards tab still
  performs a full `PUT` of the whole record — dirty-field tracking is
  UI-only (an editor affordance and a changed-field summary in the save
  message), not a smaller wire payload.
- **No server-enforced permissions/RBAC/RLS.** The Permissions tab
  (including the new principal → role `assignments` list) is
  documentation/design metadata; picoweb does not read any of it to
  authorize a request.
- **No atomic master-child batch writes.** "Save All" issues sequential
  authenticated `PUT`/`POST` calls per row and reports partial failures;
  a crash or error partway through can leave some child rows saved and
  others not.
- **BSO1 cards are not queryable.** Fast Serial (BSO1) records live in a
  separate raw byte space from JSON cards and are invisible to
  `/wal/query`, `/wal/list/`, and the schema/validation engine.
- **`public_read`/readonly/nullable/max length are still just what the
  schema says.** `public_read` is a design flag, not an access-control
  gate (picoweb doesn't have a public/private read distinction to
  enforce). `readonly`/`nullable`/`max_lengths` **are** enforced
  server-side by `picowal_validate.c`, unlike `public_read`.

### Regenerating IDE assets

`src/ide_assets.c` (the compiled-in portal/workspace HTML/JS) is
**committed** — a normal `make` never needs the sibling
`picoscript`/`baremetaljstools` checkouts. To regenerate it after
`picoscript`'s `docs/index.html` (or `vm/pico_hooks.js` / `picoc.js` /
`picovm.js`) changes, after `baremetaljstools`'s `src/BareMetal.Binary.js`
changes, or after editing `tools/ide_server_bridge.js` /
`tools/ide_picowal_workspace.html`:

```sh
make gen-ide-assets   # requires python3 + ../picoscript and ../baremetaljstools checked out
```

`tools/gen_ide_assets.py` reads `../picoscript/docs/index.html` (the
sibling repo's own generated portal — run that repo's `gen_site.py`
first if you need a newer version) and injects
`tools/ide_server_bridge.js` immediately before its last `</body>`; the
result becomes `IDE_HTML`. `tools/ide_picowal_workspace.html` is read
directly (it lives in this repo) and becomes `IDE_PICOWAL_HTML`. Neither
`picoscript` nor `baremetaljstools` is ever modified by this process —
only read from and vendored/injected into the generated `src/ide_assets.c`.

`BareMetal.Binary.js` is vendored **verbatim** (never modified) from the
sibling `baremetaljstools` checkout — picoweb does not edit it, only
embeds it, exactly like the `picoscript` portal/VM/compiler JS above.

---

## Log replication (multi-reader / single-writer)

Replication is segment-aware: a replica doesn't stream a single growing
file, it discovers the primary's current set of WAL segments (sealed +
leading) and `base.dat`, fetches whichever it's missing, and then
tail-follows the leading segment for new bytes — correctly handling
rotation (the leading segment sealing and a new one opening) without
losing or duplicating bytes.

**Primary side** — `--picowal-repl` (or `--picowal-repl-prefix=/repl/`,
which implies it) exposes:

- `GET {prefix}status` → `{"write_off":N,"leading_wal_id":N,"next_seq":N,"sector_size":512}`
- `GET {prefix}segments` → list of known segments:
  `{"segments":[{"id":N,"gen":N,"sealed":true|false,"bytes":N}, ...]}`
- `GET {prefix}segment/{id}/{gen}` → full raw bytes of a sealed segment
  (used by a replica bootstrapping or catching up on a segment it doesn't
  have yet)
- `GET {prefix}stream/{id}/{off}` → raw bytes `[off, write_off)` of the
  **leading** segment only, `Content-Type: application/octet-stream`,
  with `X-Picowal-From`/`X-Picowal-Chunk-Len`/`X-Picowal-Write-Off`
  response headers
- `POST {prefix}ack/{id}/{off}` → replica acknowledges it has durably
  persisted bytes up to `off` in segment `id`; this is what unblocks a
  primary-side commit made with `PICOWAL_DURABILITY_REMOTE`

All endpoints always require `--picowal-write-token`/`PICOWAL_WRITE_TOKEN`
via `X-PW-Write-Token` — independent of `--oidc-cookie-auth`, since
replication is a machine-to-machine trust boundary that streams the
*entire* raw, schema-unvalidated log (much larger blast radius than a
single static-pack write). The feed refuses to serve at all (503) if no
token is configured.

**Replica side** — `--picowal-replica-of=http://host:port/prefix/`
spawns a background thread that polls the primary's `status`/`segments`
endpoints, fetches any sealed segments (or `base.dat`) it's missing via
`segment/{id}/{gen}`, then tail-follows the current leading segment via
`stream/{id}/{off}` and replays new bytes into the local picowal volume
(no TLS — run this over a trusted network, e.g. a VPC or WireGuard mesh,
or front it with a TLS-terminating sidecar). Once replication starts, the
node marks its local picowal volume read-only: all `/wal/`, static-pack,
and pico-route mutation routes return `503 Service Unavailable` ("read
replica: writes must go to the primary") instead of writing locally, so
replicas can never silently diverge from the primary's log. Reads
(`GET`/`HEAD`) keep serving out of the continuously-updated local copy.

Example (primary on `:8080`, replica on `:8081` polling it):

```sh
# primary
./picoweb --picowal-device=/var/lib/picowal --picowal-format \
          --picowal-write-token=change-me-to-a-real-secret \
          --picowal-repl --picowal-repl-prefix=/repl/ \
          8080 wwwroot

# replica
./picoweb --picowal-device=/var/lib/picowal-replica --picowal-format \
          --picowal-write-token=change-me-to-a-real-secret \
          --picowal-replica-of=http://primary-host:8080/repl/ \
          8081 wwwroot
```

Point a load balancer's read traffic at replicas and all write traffic
at the primary for a simple multi-reader/single-writer topology.

### Gossip-based leader election (`--picowal-node-id` / `--picowal-followers`)

Layered on top of the replication feed above, a replica can optionally
join a small **quorum-based leader election** so that a static set of
replicas can auto-promote one of themselves to writer if the primary
disappears, instead of requiring an operator to manually re-point a new
primary.

```sh
# replica, additionally opted into gossip election
./picoweb --picowal-device=/var/lib/picowal-replica --picowal-format \
          --picowal-write-token=change-me-to-a-real-secret \
          --picowal-replica-of=http://primary-host:8080/repl/ \
          --picowal-node-id=replica-host:8081 \
          --picowal-followers=replica-host:8081,replica2-host:8082,replica3-host:8083 \
          8081 wwwroot
```

- `--picowal-node-id=HOST:PORT` — this node's own identity; must appear
  in `--picowal-followers`.
- `--picowal-followers=ID1,ID2,...` — the fixed, statically-configured
  set of registered followers (replicas only — do not include the
  primary). Every node in the set should be started with the same
  `--picowal-followers` list.

Each follower runs a background gossip tick (every ~500ms) that checks
whether its primary looks healthy (a run of consecutive failed
`/repl/status` polls). While the primary is healthy, nothing happens.
Once a follower detects the primary is down, every healthy follower
independently and deterministically nominates the same candidate (the
lexicographically-smallest registered follower id **not already known
to be dead** — see below) and gossips its vote to the others via
`POST {prefix}vote` (fire-and-forget, short timeout, gated by the same
`--picowal-write-token`). The moment **any** follower observes **more
than 50% of the registered followers** have voted for a candidate, it
records that candidate as the known leader — symmetrically, not just
the winner — and, if that candidate is itself, self-promotes: it stops
pulling from the dead primary, flips its own picowal volume back to
read-write, and starts serving the primary-side replication feed.

Every OTHER follower (not just the winner) then automatically
re-points its own repl-client at the newly-confirmed leader via
`picowal_repl_client_retarget()` — the sentence above used to read
"could in principle re-point at it"; this is now real, not aspirational.
If that confirmed leader later fails ITS health checks too (a normal
event over a cluster's lifetime — leaders can fail more than once),
it's added to a per-process dead-candidate exclusion list so the next
election picks a genuinely different node instead of deadlocking by
re-nominating the same now-dead node forever.

Check election state via `GET {prefix}status` (same token-gated auth):

```sh
curl -H 'X-PW-Write-Token: ...' http://replica-host:8081/gossip/status
# {"self":"replica-host:8081","term":1,"candidate":"replica-host:8081","votes":3,"followers":3,"quorum":2,"promoted":true,"known_leader":"replica-host:8081"}
```

**This is deliberately not a full consensus protocol.** There is no
log-matching, no fencing token, and no protection against split-brain
if the old primary later comes back online while a new leader has
already been promoted — both would accept writes simultaneously. It
relies on: a static, operator-configured follower list (no dynamic
membership changes), deterministic candidate selection so followers
don't need a real campaign phase, and best-effort gossip over plain
HTTP. Treat it as a pragmatic "mostly cooperative" failover aid, not a
guarantee against split-brain — an operator (or an external fencing
mechanism) should still confirm the old primary is truly dead before
trusting a promoted node's writes as authoritative.

> This same protocol was ported to a separate Python service
> (`wavesearch-api`, elsewhere in this workspace) and tested end-to-end
> against real multi-node bootstrap and failover scenarios. Two real
> bugs found during that port — dead-candidate re-election never
> making forward progress past a second leader failure, and a
> stale-failure-count bug when retargeting to a newly-confirmed leader
> — were back-ported here (`picowal_gossip.c`/`picowal_repl_client.c`);
> see `tests/test_gossip_backport.c` for an isolated unit test of both
> fixes run against the real production file.

### Control-plane-fenced clustering (`--picowal-cluster` + fence)

When picoweb runs as a capsule under **picocluster**, the picowal
replication above is driven by an external control plane instead of
picoweb's own gossip election. In this mode the control plane is the
**only** primary selector and every write on the primary is authorized
by a mandatory, per-write **fence** — so a partitioned former primary
cannot keep accepting writes.

- `--picowal-cluster` — mark this volume as control-plane-managed. It
  **rejects** the autonomous gossip-promotion flags
  (`--picowal-node-id` / `--picowal-followers`) and **requires the fence
  below for writable startup** (picoweb refuses to start a clustered
  writable volume without a working fence).
- `--picowal-fence-sock=PATH` — the local control plane's data-fence
  Unix socket. Before every picowal mutation, picoweb asks it "am I
  still the committed primary for this group at this epoch?" and fails
  **closed** (HTTP 503) on any denial. A bounded, monotonic lease
  (≤ 500 ms) avoids a round-trip per write.
- `--picowal-fence-group=NAME` — the data-group id (the capsule name).
- `--picowal-fence-epoch=N` — the assignment epoch this instance was
  launched at; a stale epoch is rejected by the fence.
- `--picowal-fence-node=ID` — this node's id; must equal the committed
  primary.

The replication token still comes from `--picowal-write-token` /
`PICOWAL_WRITE_TOKEN` (the control plane injects the env from a 0600
file); the fence carries no secret. When these flags are **absent**
picoweb behaves exactly as before (standalone or gossip-driven), so
existing deployments are unaffected. Under picocluster, all of this is
configured automatically by the supervisor — see the picocluster repo's
`docs/data-plane.md`. `PICOWEB_LISTEN_ADDR=<ipv4>` pins listeners to one
address so several instances can share a port on distinct per-node
addresses of one host.

---

## Virtual-partition ownership routing & the query/report gateway (`--picowal-partition-nodes`)

On top of the single-writer replication/gossip model above, picowal can
also be run as a **horizontally-sharded cluster**: a fixed pool of nodes
that each own a disjoint slice of the record space, so writes for a
given tenant scale across multiple independent volumes instead of a
single primary. This is orthogonal to (and can be combined with)
replication — each node in the partition pool is its own independent
picowal volume; partitioning decides *which* node a given record lives
on, not how that node protects its own data.

### Ownership: 1000 virtual partitions, rendezvous (HRW) hashing

```sh
./picoweb --picowal-device=/var/lib/picowal --picowal-format \
          --picowal-write-token=change-me \
          --picowal-node-id=10.0.0.1:8080 \
          --picowal-partition-nodes=10.0.0.1:8080,10.0.0.2:8080,10.0.0.3:8080 \
          --picowal-partition-mode=redirect \
          8080 ./www 4 200
```

- `--picowal-partition-nodes=ID1,ID2,...` — the fixed node pool (reuses
  `--picowal-node-id` for this node's own identity).
- `--picowal-partition-tenant-map=` (optional) — per-tenant subsets of
  the pool, for multi-tenant clusters that don't want every tenant
  spread across every node; a tenant absent from the map falls back to
  the full global pool.
- `--picowal-partition-mode=redirect|proxy` (default `redirect`) —
  what a non-owner node does with a write for a record it doesn't own:
  `redirect` returns `307` + `X-PW-Partition-Owner: host:port` for the
  client to retry against directly; `proxy` transparently forwards the
  request over HTTP and relays the owner's response back (adding
  `X-PW-Proxied-From`), so clients never need partition awareness.

Each record's virtual partition is `hash(key) mod 1000`; each virtual
partition's owner is the pool node that wins rendezvous (HRW) hashing
over `(vpart, node_id)` — every node computes the same answer
independently, with no coordination, gossip, or central directory
required. (Rendezvous hashing means adding/removing a node only
reshuffles the ~1/N share of partitions it's responsible for, not the
whole keyspace.)

### Query/report gateway: read across every shard from any node

Because ownership is per-record, a full scan/query has no single
owner — `POST /wal/query` and `POST /wal/report` therefore **fan out**
to every node in the tenant's pool automatically whenever partitioning
is enabled: the receiving node serves its own shard in-process, fetches
every other node's shard over a plain HTTP round trip, and merges the
per-shard `{"rows":[...],"count":N}` results into one response — so any
node in the pool can be queried and will return the full, cluster-wide
result set, not just its own local records. A shard that's unreachable
is skipped rather than failing the whole request; the merged response
then includes `"partial":true,"shards_ok":N,"shards_total":M` so
callers can detect degraded (partial) results. The whole query only
fails if every shard is unreachable.

The `X-PW-Partition-Hop: 1` header (set automatically on the internal
forwarded requests) stops a node that receives a forwarded query from
fanning out a second time.

There's no separate gateway process — every `picoweb` node can act as
the entry point for a query and performs the fan-out/merge itself,
using the exact same `--picowal-partition-nodes`/`--picowal-partition-tenant-map`
configuration as the write-ownership routing above.

```sh
curl -H 'X-PW-Write-Token: ...' -X POST --data-binary $'S:id,name\nF:10' \
     http://10.0.0.2:8080/wal/query
# returns rows from ALL THREE nodes' volumes, merged, regardless of
# which node the client happened to hit
```

See `test_picowal_partition.sh` for an end-to-end 3-node test covering
ownership agreement, redirect/proxy write routing, and the query
fan-out gateway.

### List gateway: `GET /wal/list/{pack}` also reads across every shard

`GET /wal/list/{pack}` has the same "no single owner" problem as query: a
full-pack listing must see records regardless of which node happens to own
each one. When partitioning is enabled, it fans out exactly like
`/wal/query` — the receiving node serves its own shard in-process, fetches
every other node's shard over a plain HTTP round trip, and merges the
per-shard `records` arrays into one response, de-duplicating by record id
defensively (a node briefly considered "owner" during a partition-pool
membership change shouldn't be able to double-count a record). A shard
that's unreachable is skipped rather than failing the whole request, and
the merged response gains `"partial":true,"shards_ok":N,"shards_total":M`
exactly like the query gateway. `X-PW-Partition-Hop: 1` again marks
already-forwarded requests so a node serves them from its local shard only
instead of fanning out again.

### Metadata (name/schema/permissions) replication across the pool

Metadata packs 1 (name), 2 (schema), and 3 (permissions) are **not**
sharded like per-record data — every node in the tenant's pool is expected
to hold an identical copy, so `GET /wal/metadata/...` always stays a local
read. That means a `PUT`/`DELETE` against any of them has to fan out to
the **whole** pool instead of routing to a single owner: whichever node
receives the mutation applies it locally, then forwards the same
`PUT`/`DELETE` to every other node in the tenant's pool (carrying the same
cookie/write-token credentials, plus `X-PW-Partition-Hop: 1` so the peer
applies it locally rather than re-forwarding). If every peer accepts it
(or, for a `DELETE`, already didn't have the key), the original caller
sees the normal `204`/`201`; if any peer is unreachable or rejects it, the
caller gets a `502 Bad Gateway` explaining how many peers failed, rather
than a `204` that silently hides nodes drifting out of sync.

```sh
curl -H 'X-PW-Write-Token: ...' -X PUT --data-binary '{"fields":"id,name"}' \
     http://10.0.0.1:8080/wal/metadata/schema/12
# applied on 10.0.0.1 AND replicated to 10.0.0.2 / 10.0.0.3 before the
# response is sent back
```

See `test_picowal_partition.sh` for coverage of metadata replication (both
`redirect` and `proxy` partition modes), the list gateway fan-out, and
confirmation that unauthenticated metadata mutations are rejected.

### PicoScript `Storage.*` hooks are partition-aware too

Dynamic PicoScript routes (`--picowal-code-card`, see "Static content and
dynamic routes straight from picowal" above) read/write raw bytes via
`Storage.AddCard`/`ReadCard`/`UpdateCard`/`DeleteCard`, bypassing `/wal/`'s
JSON-schema pipeline entirely. When partitioning is enabled, these hooks
resolve the owner of the `(pack, record)` key being touched exactly like
`/wal/` does, and — if the owner isn't this node — transparently forward
the raw operation to it over an internal, non-schema-validated endpoint
(`{code-prefix}_raw/{pack}/{rec}`, not intended to be called directly by
clients, gated by the same `X-PW-Write-Token`/OIDC trust boundary as the
bytecode-deploy path). `Storage.AddCard`'s auto-increment placement scan
resolves the owner of *each candidate record* independently (since
different candidate ids can land on different owners) and does a remote
existence-check-then-claim for any candidate it doesn't own itself — so a
PicoScript card behaves identically whether it's running on the record's
owner or not. See `test_pico_route_partition.sh` for an end-to-end test
that deploys a router card to 3 partitioned nodes and confirms a card
added via one node is readable through every node in the pool.

### `static_pack` (`/site/`) and the IDE raw card store (`/ide/card/`) are partition-aware too

Both of these serve/store raw bytes directly on a picowal card the same
way `Storage.*` does above, so both are partition-aware for **all** of
GET/HEAD/PUT/DELETE (not just writes, unlike `/wal/`'s REST API, which
assumes the node pool is itself fully replicated and only proxies
mutations) -- a node that isn't the current owner of a given `(pack,
record)` redirects or transparently proxies to the true owner, using the
request's tenant context (`X-PW-Tenant-Id` / `Host` first component) to
resolve ownership exactly like `/wal/` does. See `test_ide_partition.sh`
for an end-to-end test that publishes static content and IDE card data
via one node in a 3-node proxy-mode pool and confirms both are readable,
writable, and correctly MIME-typed through every node.

### Surfacing partition/ownership info to admin & GUI tooling

Two read-only JSON surfaces let admin tooling display partition topology
without needing to re-derive it from CLI flags:

- `GET /wal/partitions` — a standalone topology summary:
  ```json
  {"enabled":true,"mode":"proxy","self":"10.0.0.1:8080",
   "vpartitions":1000,"node_count":3,
   "nodes":["10.0.0.1:8080","10.0.0.2:8080","10.0.0.3:8080"]}
  ```
  (`{"enabled":false}` if partitioning isn't configured on this node.)
- `GET /wal/forms/{pack}` — the existing data-driven CRUD form spec now
  also includes a `"partition"` field with the same shape, so a GUI
  rendering a pack's form can show which node it's talking to and how
  many peers share the tenant's pool alongside the form itself.

This is a *topology* summary (node pool, mode, vpartition count), not a
precomputed per-record ownership map — resolving the owner of any given
`(pack, record)` is already a cheap, on-demand hash computation (see
`picowal_partition_of_key`/`picowal_partition_owner`), so there's nothing
worth caching per-record for 1000 vpartitions here.

---

## Performance flags

picoweb is built around **calculation hit at startup, pointer copies at runtime**.
Anything optional follows the same rule: pre-compute, never mutate the hot path.

### `MSG_ZEROCOPY` (5th positional arg `ZC_MIN`)

When `ZC_MIN > 0`, accepted client sockets opt in to `SO_ZEROCOPY` and
`sendmsg()` calls whose remaining payload is `>= ZC_MIN` bytes pass
`MSG_ZEROCOPY`. The kernel pins the user pages and skips the data copy.

- **Default `0` (off)** — per the kernel docs, MSG_ZEROCOPY is a regression
  for sends below ~10 KB because the page-pinning and completion-queue
  overhead beats the saved memcpy. Useful threshold: `16384` and up.
- **Soft-fail** — older kernels (pre-4.14) or restrictive policies make
  `setsockopt(SO_ZEROCOPY)` return `EPERM`/`ENOPROTOOPT`. We log one warn
  and continue without ZC for that connection.
- **`ENOBUFS` retry** — if the kernel's optmem cap is hit while ZC sends are
  in flight, we retry the same iovec without `MSG_ZEROCOPY` rather than
  dropping the connection.
- **`MSG_ERRQUEUE` drain** — completion notifications fire `EPOLLERR`. We
  drain via `recvmsg(MSG_ERRQUEUE)`, recognise `SO_EE_ORIGIN_ZEROCOPY`,
  and only close on a real (non-ZC) error.

### Pre-compression: `picoweb-compress` (always on)

At startup we run a hand-written block-LZ encoder (vendored — no third-party
deps) over every text-y resource (`text/*`, `application/json`, `application/javascript`,
`application/xml`, `image/svg+xml`). The compressed bytes live in the same
immutable arena. If the result isn't smaller than the original it's dropped.

The encoder is **wire-compatible with [BareMetal.Compress.js](https://github.com/WillEastbury/BareMetalWeb)**,
so the existing browser-side decoder works as-is. Tokens recognised in
`Accept-Encoding`:

- `picoweb-compress` (preferred)
- `BareMetal.Compress` (legacy alias)

When a client opts in, picoweb swaps to a precomputed head + body pair
(`Content-Encoding: picoweb-compress`, `Vary: Accept-Encoding`). Chrome bytes
are baked into the compressed stream so the iovec collapses from 4 segments
to 2.

Typical wins on real text content: **~5× on repetitive HTML/CSS/JS, ~2-3×
on natural prose**. Random binary is correctly bypassed (no false positives).

### Why other "go faster" options aren't simple flags

These come up a lot. Here's the honest read on each:

| Option            | Status        | Why |
|-------------------|---------------|-----|
| **`io_uring`**    | Runtime flag  | `./picoweb --io_uring` selects the io_uring worker (raw syscalls, no liburing). Same business logic as the default epoll worker. See *io_uring backend* below. |
| **`--dpdk`**      | Reserved flag | `./picoweb --dpdk` is wired in but errors out at startup — the DPDK + userspace TCP/TLS path lives under `userspace/` as a foundation, not a runnable backend. See `userspace/DESIGN.md`. |
| **`sendfile()`**  | Won't ship    | We back resources with anonymous mmap (one arena per worker), not file fds. `sendfile()` requires per-resource fds and would force a `read`+`sendfile` pair per request — a regression vs the current single `sendmsg`. The arena model is already zero-copy in userspace; the only kernel-side win left is `MSG_ZEROCOPY`. |

### `io_uring` backend (`./picoweb --io_uring`)

A second worker implementation lives in `src/server_uring.c` and is
linked into the same `picoweb` binary as the default epoll worker.
At runtime, `--io_uring` makes `main.c` spawn `uring_worker_main`
threads instead of `epoll_worker_main`:

```
./picoweb 8080 wwwroot 4 100              # default (epoll)
./picoweb --io_uring 8080 wwwroot 4 100   # io_uring
```

Mutually exclusive with `--dpdk`. The runtime shape, the parser, the
jumptable lookup, the `picoweb-compress` variant swap, and the
keep-alive bookkeeping are unchanged. What's different:

- **No `<liburing.h>`.** The worker calls `io_uring_setup` and
  `io_uring_enter` directly via `syscall()` and uses the SQ/CQ ring
  layout the kernel exposes through `<linux/io_uring.h>`. Same
  no-third-party-deps stance as the rest of picoweb.
- **One ring per worker, 1024 SQ entries.** `IORING_FEAT_SINGLE_MMAP`
  is honoured when the kernel reports it (5.4+).
- **Ops used:** `IORING_OP_ACCEPT` (one-shot, re-armed on every
  completion), `IORING_OP_RECV`, `IORING_OP_SENDMSG`,
  `IORING_OP_CLOSE`. The 56/8-bit user_data carries the connection
  index plus a 1-byte op tag.
- **Same partial-send loop.** `submit_sendmsg` walks the up-to-4
  iovec segments, skips `bytes_sent` worth of prefix, hands the
  remaining slice to the kernel, and reissues on partial completion.

Status: passes the same regression suite as the epoll backend
(`test_pages.sh`, `test_compress.sh`) plus a dedicated
`test_uring.sh` smoke pack. **Permanent opt-in** — epoll remains the
default until io_uring has been burned in under load.

What's *not* in the io_uring backend yet (deliberate scope cuts —
straightforward extensions, just not in the spike):

- Multishot accept / multishot recv. 5.19+ kernels only; the spike
  targets WSL2's 5.15 line.
- Registered fds and fixed buffers. Next-level perf; design intact.
- Idle-timer eviction. The epoll backend's per-conn idle-timer is
  not yet ported; under abusive slow-loris-style clients you'll want
  the epoll backend.

`MSG_ZEROCOPY` IS supported via `IORING_OP_SENDMSG_ZC` (Linux 6.0+):
the worker uses the same `ZC_MIN` threshold as the epoll backend,
ignores the `IORING_CQE_F_NOTIF` "kernel done" CQE (response bytes
live forever in the immutable arena), and on older kernels that
return `-EINVAL`/`-EOPNOTSUPP` for the new opcode it logs once,
flips the threshold to 0, and resubmits the same payload as a plain
`SENDMSG` — no requests are dropped during the fallback.

### `--dpdk` flag

The `--dpdk` flag is **reserved**: it's parsed and validated, but
running with it produces a clear error and exits. The intent is to
wire it through to a DPDK-driven userspace TCP+TLS stack, the
foundation for which lives under `userspace/`:

```
$ ./picoweb --dpdk 8080 wwwroot
picoweb: --dpdk backend is not built into this binary.
         See userspace/DESIGN.md for the integration plan.
         The flag is reserved; running with it now is a
         hard fail rather than a silent fallback.
```

The reasons we haven't lit it up: DPDK requires librte_eal et al.,
hugepages reserved, a NIC bound to vfio-pci, **and** the userspace
TCP retransmit / RTO / SACK / CC code that `userspace/tcp/tcp.c` only
sketches. WSL has no NIC bindable for vfio-pci either, so it cannot
even be smoke-tested in dev. See `userspace/DESIGN.md` for the
honest scope and the months-long roadmap.

---

## Filesystem conventions

```
wwwroot/
├── _default/                # fallback vhost (optional)
│   └── index.html
├── example.com/             # vhost — served for Host: example.com
│   ├── index.html
│   ├── css/
│   │   └── style.css
│   ├── _chrome/             # OPTIONAL header/footer wrap for HTML pages
│   │   ├── header.html
│   │   └── footer.html
│   └── _pages/              # OPTIONAL "virtual root" of chromed pages
│       ├── index.html       # → served as /  AND  /index.html
│       ├── about.html       # → served as /about.html
│       └── blog/
│           └── post1.html   # → served as /blog/post1.html
└── another.example/
    └── index.html
```

Anything under `wwwroot/<dirname>/` is served as a virtual host matching
`Host: <dirname>`. Hostname matching is case-insensitive (lowercased once at
parse). Any directory whose name starts with `_` is hidden from URL space
and reserved for picoweb conventions (currently `_chrome` and `_pages`).

### Virtual hosts

To add a vhost: create `wwwroot/<hostname>/`, drop content into it, restart.
That's it. The `Host:` header on the request selects the vhost. If the host
isn't found, `_default/` (if present) is used; otherwise `404`.

### `_chrome/` — header/footer wrap for HTML

Drop `header.html` and `footer.html` into `wwwroot/<host>/_chrome/`. At boot
they're slurped into the arena once and shared by every HTML resource for
that host via a single 32-byte `chrome_t { hdr*, hdr_len, ftr*, ftr_len }`
struct. At request time, an HTML response is sent as a 4-segment `iovec`:

```
[ pre-baked HEAD ][ chrome.hdr ][ body ][ chrome.ftr ]
```

`Content-Length:` in the head is pre-baked to include the chrome bytes, so
there's no formatting work at runtime. Non-HTML resources (CSS, JS, images,
JSON, …) are served raw — they don't get wrapped.

`HEAD` requests get the same headers (with the same total length advertised)
but no body, as required by HTTP.

### `_pages/` — opt-in chromed page tree

If `wwwroot/<host>/_pages/` exists, it acts as a **virtual root**: every
file inside it is mapped into URL space with the `_pages` prefix stripped.

```
_pages/index.html         → /  AND  /index.html
_pages/about.html         → /about.html
_pages/blog/post1.html    → /blog/post1.html
```

`_pages/` entries **win** on URL collisions with regular content (the lookup
prefers `_pages/index.html` over a top-level `index.html` if both exist),
silently. Combined with `_chrome/`, this gives you two well-defined
authoring patterns:

| You want…                           | Then…                                        |
|-------------------------------------|----------------------------------------------|
| Files served exactly as-is          | Drop them under `wwwroot/<host>/`            |
| Pages wrapped in shared chrome      | Drop them under `wwwroot/<host>/_pages/`     |
| Both, with chromed pages winning    | Use both — `_pages/` takes priority          |

`/css/style.css`, `/favicon.ico`, etc. continue to serve at their natural
URLs from outside `_pages/` regardless.

---

## HTTP behaviour

- **HTTP/1.1 only.** `HTTP/1.0` requests get `505`.
- **Methods:** `GET`, `HEAD` are served. `POST`, `PUT`, `DELETE` answer
  `405 Method Not Allowed` with `Allow: GET, HEAD`. Anything else / malformed
  → connection closed.
- **Keep-alive by default**, capped at 100 requests per connection (configurable
  via the 4th CLI arg) and 10 s of idle time. After the cap or timeout the
  next response carries `Connection: close`.
- **Request headers are mostly ignored.** picoweb reads `Host:` (for vhost
  routing) and `Connection:` (for `close` / `keep-alive`). All other headers
  are skipped by the parser without inspection.
- **Bounds-checked parsing.** Hard limits on request line, URI, hostname
  charset and length; path-traversal (`..`) is rejected at parse time.
- **MIME types** come from a static, hard-coded extension table in
  `src/mime.c` — looked up once at build time, then baked into the head.
  Unknown extensions get `application/octet-stream`.
- **No request bodies, no chunked transfer, no range requests, no query
  strings** (path matched verbatim against the pre-built table).
- **Pipelining is intentionally not supported.** Browsers don't pipeline in
  practice. picoweb processes one request at a time per connection and
  leaves any extra bytes in the read buffer for the next loop iteration.

---

## Built-in endpoints

Both endpoints are inserted as **regular flat-table entries on every host**
— so they're served at zero hot-path cost (one lookup, no special-case
branch).

### `GET /health`

Returns `200 OK` with body `OK`. Body is in `.rodata`, no allocation.
Useful for load balancers, k8s readiness probes, etc.

```
$ curl -i http://localhost:8080/health
HTTP/1.1 200 OK
Server: picoweb
Content-Type: text/plain; charset=utf-8
Content-Length: 2
Connection: keep-alive

OK
```

### `GET /stats`

Returns plain-text key/value stats:

```
uptime_seconds=000000000007
total_requests=000000001224703
p95_microseconds=000000000004
p98_microseconds=000000000004
```

- `uptime_seconds` — wall time since boot.
- `total_requests` — sum of completed requests across all workers.
- `p95_microseconds` / `p98_microseconds` — percentile of per-request
  service time (parse → end-of-send), aggregated across all workers,
  windowed over the last 5 minutes.

**How it stays off the hot path:**

- Each worker has its own `metrics_t` in thread-local storage. The hot path
  records a single TSC sample (`rdtsc` on x86-64, `mrs cntvct_el0` on
  aarch64) and bumps one bucket in a per-worker per-second histogram. **No
  atomics. No locks. No shared state.**
- A background updater thread aggregates across workers once per second,
  computes percentiles, and rewrites the digit bytes of `/stats`'s body
  **in place**. The body length is fixed; only the digit characters change.
  Readers may at worst see one digit position with a half-old/half-new byte,
  which still decodes as a valid integer.
- The `resource_t` for `/stats` lives in the immutable arena; only the
  bytes its `body` pointer references are in a separate writable mmap
  region.

---

## SIMD acceleration

`src/simd.h` provides three portable inline primitives, dispatched at
**compile time** based on `__SSE2__` / `__ARM_NEON`:

| Primitive                             | x86-64       | aarch64                | Fallback |
|---------------------------------------|--------------|------------------------|----------|
| `metal_eq_n(a, b, n)`                 | `pcmpeqb` + `pmovmskb` | `vceqq_u8` + `vminvq_u8` | `memcmp` |
| `metal_lower_simd(p, n)` (ASCII A→a)  | signed `cmpgt` mask trick | unsigned `vcgtq` / `vcltq` | scalar  |

Used on the hot path for hostname equality compare in `flat_lookup` and for
hostname lowercasing in the request parser. UTF-8 / high-bit bytes are
correctly preserved (signed compare on SSE2 makes them negative and they
fall outside `[A,Z]` so no transform is applied; verified with `é = 0xc3
0xa9` etc.).

The chosen path is reported in the startup banner: `simd=x86-64 SSE2`,
`simd=aarch64 NEON`, or `simd=scalar`.

---

## Performance

Numbers from a typical Linux box (single CPU socket, WSL2 Ubuntu, Linux
6.x), serving the bundled `localhost/index.html`:

| Workload                            | Throughput     |
|-------------------------------------|----------------|
| `wrk -c 64 -t 1` (single client)    | ~250k req/s    |
| 4 × `wrk -c 64 -t 1` aggregated     | ~810k req/s    |
| `/stats` p95 latency under load     | ~4 µs          |
| `/stats` p98 latency under load     | ~4 µs          |

Throughput is gated by the kernel's TCP/sendmsg path long before the
userspace code matters. Any further gains would have to come from
`io_uring`, `MSG_ZEROCOPY`, `sendfile`, or kernel bypass (DPDK / AF_XDP).

---

## Limits / hard caps

| Knob                                    | Default | Where set                |
|-----------------------------------------|---------|--------------------------|
| Listen backlog                          | 4096    | `server.c`               |
| Connection pool size (per worker)       | 4096    | `server.c`               |
| Max requests per keep-alive connection  | 100     | CLI arg 4 (0 = unlimited)|
| Idle timeout                            | 10 s    | `server.c`               |
| Read buffer per connection              | 8 KiB   | `pool.h`                 |
| Max request line + headers              | 8 KiB   | `pool.h` / `http.c`      |
| Max URI length                          | 2 KiB   | `http.c`                 |
| Max hostname length                     | 253 B   | `http.c` (DNS limit)     |
| Max chrome fragment size                | 1 MiB   | `jumptable.c`            |
| Stats latency window                    | 300 s   | `metrics.h`              |

These are all single-`#define` changes — there's no config file. The point
is to fail fast at well-defined limits rather than bloat code with options.

---

## What's deliberately NOT supported

- TLS in the kernel-mode HTTP server (terminate at a reverse proxy, or use
  the in-tree **userspace TLS 1.3 stack** under `userspace/` — see
  [`userspace/DESIGN.md`](userspace/DESIGN.md))
- HTTP/2 or HTTP/3
- `gzip` / `brotli` (the in-tree codec is **`picoweb-compress`** —
  vendored block-LZ77, wire-compatible with [BareMetal.Compress.js](https://github.com/WillEastbury/BareMetalWeb).
  Adding a second codec would double per-resource compressed copies for
  no real benefit; modern browsers happily accept the custom token over
  `Accept-Encoding`)
- Chunked transfer encoding
- Request bodies of any kind (`POST` returns `405`)
- Range requests
- Query strings (paths matched verbatim)
- File watching / hot reload (restart the process)
- Dynamic content / templating beyond the static `_chrome/` wrap
- Logging beyond `metal_log` to stderr
- Authentication / access control
- IPv6 (yet)

These are conscious omissions, not bugs. picoweb is what's left when you
delete every feature that costs you performance you don't need.

---

## Source layout

```
src/
  main.c           args, signal setup, spawn workers
  arena.{c,h}      bump allocator + mprotect freeze
  pool.{c,h}      fixed connection pool
  jumptable.{c,h}  flat (host, path) hashtable; build + lookup
  http.{c,h}       request parser + method/host/path validation
  mime.{c,h}       extension → MIME table
  metrics.{c,h}    per-worker TSC histograms; /health + /stats build
  server.{c,h}     epoll worker loop, conn lifecycle, sendmsg state machine
  simd.{h}         SSE2/NEON inline primitives + scalar fallback
  util.{c,h}       FNV-1a, monotonic time, lowercase, log/die
  api.{c,h}        JSON file API + picowal REST + OIDC/PicoSTS session auth
  static_pack.{c,h}  serves static content straight from a picowal card
  pico_route.{c,h}   dynamic HTTP routes rendered by PicoScript bytecode
  picowal_partition.{c,h}  virtual-partition ownership routing/proxying
  ide.{c,h}        hosted PicoScript IDE (/ide/): assets, config, raw card CRUD
  ide_assets.{c,h} GENERATED (tools/gen_ide_assets.py) compiled-in portal/workspace HTML/JS
tools/
  gen_ide_assets.py        regenerates src/ide_assets.c (needs ../picoscript
                           and ../baremetaljstools)
  ide_server_bridge.js     bridges the vendored WebIDE portal to picoweb (injected
                           before </body> in ../picoscript/docs/index.html)
  ide_picowal_workspace.html  rebuilt PicoWAL workspace page (own repo, hand-authored,
                           served separately at {ide_prefix}picowal.html)
wwwroot/
  _default/        fallback vhost
  localhost/       example vhost
    _chrome/       example header.html + footer.html
    _pages/        example chromed page tree
```

Helper scripts at the repo root:

- `smoke.sh` — minimal `curl` walkthrough.
- `bench.c` — tiny in-process benchmark client.
- `bench-multi.sh` — drives multiple `wrk` clients in parallel.
- `benchsimd.sh` — same, focused on the SIMD code paths.
- `simdtest.c` — standalone unit tests for `src/simd.h`. Build with
  `gcc -O3 -o /tmp/simdtest simdtest.c`.
- `test_pages.sh` — end-to-end test of the `_pages/` and `_chrome/`
  conventions. Sets up fixtures, starts the server, drives `curl` against
  every documented behaviour, prints pass/fail.
- `test_ide.sh` — single-node IDE smoke test: the vendored upstream WebIDE
  portal structure (file sidebar, Monaco/textarea editor, Compile & Run/
  Compile & Step/Step/Reset, Disassembly/Registers/Watches debug panels,
  Guide & Reference/WebIDE/Showcase nav) at `GET /ide/`, the
  `tools/ide_server_bridge.js` wiring markers (live server, liveFetch
  override, schema translation, one PicoSTS control, deploy controls,
  full PicoWAL portal tab), the rebuilt PicoWAL workspace page at
  `GET /ide/picowal.html` across all five sub-tabs (Packs & Schemas rich
  field builder / typed Cards editor + child grids + list pagination +
  MGET / Permissions incl. assignments / Query builder + client-aggregate
  / Fast Serial BSO1 panel), route/asset serving (including the vendored
  `/ide/baremetal-binary.js`), `/ide/config`, authenticated raw card
  save/load, and the static_pack trailing-filename MIME fix.
- `test_ide_partition.sh` — 3-node proxy-mode cluster test: static_pack
  and IDE raw card reads/writes/deletes all work through every node.
- `test_picowal.sh` — picowal REST API + validator tests, including rich
  logical-type validation (`bool`/`uintN`/`intN`/`decimal`/`ascii`/`utf8`/
  `date`/`time`/`datetime`/`array_u16`/`blob`/`lookup`, `nullable`/
  `readonly`/`max_lengths` enforcement) and a schema JSON round-trip test
  asserting every new metadata key (`ordinals`, `lookup_labels`, `module`,
  `public_read`, `children`, `list_columns`, `nullable`, `readonly`,
  `max_lengths`) survives a save/reload unchanged.
- `test_picosts_auth.sh` — PicoSTS Authorization Code + PKCE login
  integration against a minimal fake `/userinfo` endpoint: userinfo/JWT
  claim validation (positive + 5 negative cases), the stateless cookie
  format, `Path=/` coverage, and cluster-safety across two independent
  picoweb processes sharing `--picosts-cookie-key`.
- `hardened.sh` / `sanitize.sh` — build-and-test loops with paranoid
  compiler flags and ASan/UBSan.

---

## Userspace TCP+TLS foundation (`userspace/`)

A pure-C TLS 1.3 + TCP/IP + AF_PACKET/AF_XDP foundation lives under
`userspace/`. **Updated: parts of this ARE now wired into the live
`picoweb` binary** (see the root `Makefile`'s `USERSPACE_TLS_SRC`) --
this section previously said "not wired into the picoweb binary
today," which is no longer accurate for the crypto/TLS pieces.
Specifically: `server_tls_kernel.c` runs the from-scratch TLS 1.3
record layer and handshake engine (`userspace/tls/`, `userspace/crypto/`)
**over ordinary kernel TCP sockets** (not AF_PACKET/AF_XDP/DPDK) --
"kernel TCP, userspace TLS" is the model that's actually live today.
The full from-scratch **TCP/IP** stack (`userspace/tcp/`) and the
AF_PACKET/AF_XDP/DPDK packet-I/O paths remain compiled but not
exercised end-to-end against a real NIC (see
[`userspace/DESIGN.md`](./userspace/DESIGN.md) for the honest, current
breakdown of what's wired vs. sketched).

**Deployment finding: on Kubernetes, AF_PACKET is the validated
packet-I/O backend; AF_XDP and DPDK are a dead end.** Both need
kernel-level integration (zero-copy driver mode + `CAP_NET_ADMIN`/
`CAP_BPF` for AF_XDP; hugepage + `vfio-pci`/SR-IOV device passthrough
for DPDK) that a standard CNI-managed pod network doesn't grant.
AF_PACKET needs only `CAP_NET_RAW` over an ordinary pod interface. See
`userspace/DESIGN.md`'s status block for the full reasoning.

**Related project**: `pios` (a separate repo/sibling directory in this
workspace) takes this same idea further with a from-scratch, bare-metal
multi-core OS (Raspberry Pi 5) whose own kernel owns the network+TCP+TLS
stack directly, with lock-free inter-core FIFOs standing in for what
sockets/AF_PACKET do here — TCP and a basic TLS 1.2 handshake + record
layer are both working there today (see that repo's own `README.md`/
`STATUS.md`).

What's real (50+ RFC-vector tests pass in `test_crypto.c` alone, plus
a separate `test_quic_primitives` binary — `cd userspace/tests && make test`):

- Crypto: SHA-256, SHA-512, HMAC-SHA256, HKDF-SHA256, ChaCha20,
  Poly1305, ChaCha20-Poly1305 AEAD, X25519, Ed25519, **RSA, ECDSA/P-256**
  — all from-scratch, no third-party crypto, validated against RFC
  vectors. (RSA/ECDSA were previously listed as "not in scope" here;
  both are now compiled into the live binary and unit-tested.)
- Full TLS 1.3 handshake: record layer (seal/open, tamper detection),
  key schedule (RFC 8448 §3 vectors), ClientHello/ServerHello/
  EncryptedExtensions/Certificate/Finished parsers and builders, an
  SNI-aware cert store with PEM decoding, session tickets.
- IPv4 + TCP build/parse with full checksums.
- Full TCP state machine: passive-open (`LISTEN → SYN-RECEIVED →
  ESTABLISHED → CLOSE-WAIT → LAST-ACK → CLOSED`), **retransmit, RTO
  (RFC 6298), fast retransmit/fast recovery (RFC 5681)**, and
  zero-window flow control — all previously listed as "not in scope,"
  all now real in `tcp/tcp.c`.
- AF_PACKET RX/TX (Linux only, compile-clean; the validated packet-I/O
  path for Kubernetes -- see the deployment finding above -- but still
  no E2E test against a real production link). AF_XDP/DPDK also
  compile but are deprioritized dead ends for this project's
  Kubernetes target (see deployment finding above).
- A **full QUIC transport + HTTP/3 + QPACK** implementation
  (`userspace/quic/`, `userspace/h3/`, `userspace/qpack/`) — real and
  RFC-vector-tested via `test_quic_primitives`, but **not yet linked
  into the live `picoweb` server** (a large body of tested code
  awaiting protocol-level integration).

What's still deliberately **not** in scope: AES-GCM is not wired into
`tls/record.c`'s dispatch (ChaCha20-Poly1305 only), TCP SYN
cookies/listen-queue protection, parser fuzzing, and an end-to-end
test of AF_PACKET against a real production NIC/CNI path (WSL has no
passthrough NIC to test against, and this hasn't yet been tried in an
actual Kubernetes pod either). AF_XDP/DPDK's own lack of E2E testing
is no longer the priority gap -- both are deprioritized regardless,
per the deployment finding above. See
[`userspace/DESIGN.md`](./userspace/DESIGN.md) for the full, current,
honestly-tracked scope and roadmap.

---

---

## `picowal` — an embedded WAL datastore with replication

Already documented in detail above (see [Storage engine](#storage-engine-wal-segments-basedat-transactions-durability),
[Log replication](#log-replication-multi-reader--single-writer), and
[Gossip-based leader election](#gossip-based-leader-election---picowal-node-id--picowal-followers)).

## License

MIT — see [LICENSE](./LICENSE).
