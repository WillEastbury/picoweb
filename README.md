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

> **Status:** working hobby project. ~2.7k lines of C, no external deps
> beyond libc + pthreads. Linux-only (uses `epoll`, `SO_REUSEPORT`,
> `accept4`).

---

## Table of contents

- [Why](#why)
- [Design highlights](#design-highlights)
- [Build](#build)
- [Run](#run)
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
- `hardened.sh` / `sanitize.sh` — build-and-test loops with paranoid
  compiler flags and ASan/UBSan.

---

## Userspace TCP+TLS foundation (`userspace/`)

A pure-C TLS 1.3 + TCP/IP + AF_PACKET foundation lives under
`userspace/`. It's the intended substrate for a future real `--dpdk`
backend, but is **not wired into the picoweb binary today**.

What's real (38 RFC-vector tests pass — `cd userspace/tests && make test`):

- Crypto: SHA-256, HMAC-SHA256, HKDF-SHA256, ChaCha20, Poly1305,
  ChaCha20-Poly1305 AEAD, X25519 — all from-scratch, no third-party
  crypto, validated against RFC vectors.
- TLS 1.3 key schedule (RFC 8448 §3 vectors green) and record layer
  (seal / open with sequence-number nonce, tamper detection).
- IPv4 + TCP build/parse with full checksums.
- TCP passive-open state machine: `LISTEN → SYN-RECEIVED →
  ESTABLISHED → CLOSE-WAIT → LAST-ACK → CLOSED`.
- AF_PACKET RX/TX skeleton (Linux only, compile-clean).

What's deliberately **not** in scope: AES-GCM, RSA / ECDSA signing,
TLS handshake message parsing (ClientHello / ServerHello), TCP
retransmit / RTO / congestion control / SACK, SYN cookies, parser
fuzzing, real DPDK binding. See [`userspace/DESIGN.md`](./userspace/DESIGN.md)
for the honest scope and roadmap.

---

## License

MIT — see [LICENSE](./LICENSE).
