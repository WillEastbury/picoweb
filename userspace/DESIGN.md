# picoweb userspace TCP + TLS — design spike

> **Status: merged to `main`.** This started as a design + foundation
> spike and has been promoted to the project's permanent userspace
> network stack (see commit history on `main`). It is not a production
> stack — the work to ship a real userspace TCP+TLS network path is
> still months of engineering — but it is the canonical home of the
> crypto, TLS, and TCP work and is exercised by 130 tests on every
> build.
>
> **What is real, here, and green (130 RFC-vector + integration tests passing):**
> SHA-256 (with runtime-dispatched **SHA-NI** HW acceleration on x86),
> HMAC-SHA256, HKDF-SHA256, ChaCha20 (with runtime-dispatched **SSE2
> 4-way** SIMD), Poly1305, ChaCha20-Poly1305 AEAD with both contiguous
> and **scatter-gather (`*_iov`)** seal paths, X25519 ECDH, TLS 1.3
> HKDF-Expand-Label and Derive-Secret (RFC 8448 §3 vectors), TLS 1.3
> record seal/open with sequence-number nonce **and** scatter-gather
> seal (`tls13_seal_record_iov` proven byte-identical to the
> contiguous path), TLS 1.3 ClientHello parser, ServerHello /
> EncryptedExtensions / Certificate / Finished wire builders,
> handshake-secret derivation, running transcript-hash helper, Finished
> compute + verify (RFC 8446 §4.4.4), IPv4 + TCP header build/parse
> with both IPv4 and TCP checksums, TCP passive-open state machine
> (LISTEN → SYN-RECEIVED → ESTABLISHED → CLOSE-WAIT → LAST-ACK), an
> **L4 pre-jump table (`pw_dispatch_t`)** routing inbound bytes by
> `(proto, dst_port)` so one TCP stack can host many services
> independently (HTTPS, HTTP, gossip, DNS, …) with strict zero-alloc
> per-conn pools and SYN-flood-safe `on_open`/`on_close` lifecycle,
> SNI-aware in-memory cert store (env + disk, PEM decoder), per-worker
> zero-allocation buffer pool, runtime CPU feature detection,
> `pw_conn` run-to-completion runtime that walks RX → TLS-open → HTTP
> slice → response_fn → TLS-seal → TX in one call.
>
> **What is sketched but not wired:** AF_PACKET I/O (compiles on
> Linux, no E2E test), DPDK pump (real `rte_*` calls under
> `-DWITH_DPDK=1`; stub mode returns -1 otherwise so the binary
> always links).
> The BearSSL-style explicit TLS engine state machine is in tree but
> still uses the spike-mode `install_app_keys` shortcut; full
> handshake hookup is the next step.
>
> **What is deliberately not in scope:**
> - **ECDSA / RSA** cert signing — Ed25519 is implemented (RFC 8032,
>   §7.1 vectors pass) and is the only signature algorithm the server
>   advertises. ECDSA / RSA add code surface without buying anything
>   we need for a single-cert spike.
> - **AES-GCM** — TLS 1.3 ChaCha20-Poly1305 only. AES-GCM costs a real
>   amount of code without a real perf win on modern CPUs that have AES-NI
>   but no SHA-NI for AES-GCM's GHASH (and vice versa). One AEAD is
>   plenty for a spike; we'll add AES-GCM if a use-case forces it.
> - **`gzip`/`brotli`/`zstd`** — the picoweb HTTP server uses
>   `picoweb-compress` (vendored, ~250 lines of LZ77, wire-compatible
>   with BareMetal.Compress.js). No third-party compression code in tree.
> - **TCP retransmit / RTO / congestion control / SACK / SYN cookies**
>   — happy-path passive open only.
> - **Receive-window-driven backpressure** — static 65535-byte window
>   today; flagged in [next steps](#open-engineering-items).
> - **Fuzz testing of parsers** — would be the right next thing once
>   the handshake actually completes end-to-end.

## Why we'd ever do this

The fastest a kernel-resident HTTP server can go is gated by:

- syscall transition cost (mitigated by `io_uring`, but not eliminated)
- SKB allocation, copy in/out of kernel
- TCP socket buffer copies
- TLS record encryption *inside* the kernel only if you opt into kTLS
  (more setup, more constraints)

A userspace stack — DPDK, AF_XDP, or AF_PACKET — bypasses some or all
of that. You poll a NIC RX ring directly, parse Ethernet/IP/TCP
yourself, run the connection state machine yourself, and write
straight back to the TX ring. With AEAD inlined in the same loop, the
whole request path is one cache-resident state machine with **zero**
kernel transitions per request (after socket setup).

The wins come at a cost: you reimplement a TCP stack and a TLS stack.
This is decades of OpenSSL / Linux kernel hardening you're throwing
out. We do not pretend this is small work.

## Scope of this branch

In the spike we deliver:

1. A real working set of **TLS 1.3 cryptographic primitives** in
   pure C, validated against RFC test vectors. No OpenSSL link, no
   wolfSSL, no BoringSSL, no libsodium.
   - SHA-256 (FIPS 180-4)
   - HMAC-SHA256 (RFC 2104)
   - HKDF-SHA256 (RFC 5869)
   - ChaCha20 (RFC 8439)
   - Poly1305 (RFC 8439)
   - ChaCha20-Poly1305 AEAD (RFC 8439)
   - X25519 (RFC 7748)
2. A **TLS 1.3 record framing + handshake** skeleton (RFC 8446).
   The full state machine is not exercised end-to-end against a
   real browser yet; the message parsers, key schedule, transcript
   hash, and AEAD wrap/unwrap are real. **Status:** record layer
   `tls/record.{c,h}` is real and round-trips green; key schedule
   `tls/keysched.{c,h}` matches RFC 8448 §3 vectors; full
   ClientHello/ServerHello parsers are NOT in this commit.
3. A **TCP state machine** skeleton (RFC 793 / 9293) with the LISTEN
   → SYN-RECEIVED → ESTABLISHED → FIN-WAIT-* transitions modelled,
   no congestion control or retransmit yet. **Status:** real and
   tested against a scripted client (passive open, data, FIN).
4. An **AF_PACKET** packet-I/O skeleton — runs in WSL, doesn't need
   DPDK, gives us a way to wire the stack to a real link in dev.
   **Status:** compiles on Linux, no E2E test.
5. A **DPDK** backend (`io/dpdk.{c,h}`) that compiles in two modes:
   stub-by-default (init returns -1, prints a clear "rebuild with
   -DWITH_DPDK=1" message — keeps the userspace tree linkable on
   WSL/CI), and full `rte_eal_init` / mempool / `rte_eth_rx_burst`
   pump under `-DWITH_DPDK=1`. Tested in stub mode (lock-in: -1
   from init/pump, no-op shutdown) by `test_dpdk_stub`.

What is **explicitly NOT** in this branch:

- AES-GCM (we have ChaCha20-Poly1305; that's enough for TLS 1.3
  interop — RFC 8446 mandates it as a mandatory cipher suite).
- RSA / ECDSA. Ed25519 (RFC 8032) is implemented; that's the only
  signature algorithm we advertise.
- TCP retransmit, RTO, congestion control, SACK, fast retransmit.
- TCP listen-queue / SYN cookies. Without these, picoweb is trivially
  DoS-able once it's on its own stack.
- Real fuzzing of the parsers. RFC test vectors prove the happy path.
  Hostile inputs are an enormous attack surface.

## Layout

```
userspace/
  DESIGN.md                  this file
  crypto/
    sha256.{c,h}             FIPS 180-4
    hmac.{c,h}               RFC 2104, on top of SHA-256
    hkdf.{c,h}               RFC 5869, on top of HMAC
    chacha20.{c,h}           RFC 8439 §2.4
    poly1305.{c,h}           RFC 8439 §2.5
    chacha20_poly1305.{c,h}  RFC 8439 §2.8 AEAD construction
    x25519.{c,h}             RFC 7748 §5
  tls/
    record.{c,h}             RFC 8446 §5 record layer
    handshake.{c,h}          RFC 8446 §4 message types and state machine
    keysched.{c,h}           RFC 8446 §7 HKDF-Expand-Label, key schedule
  tcp/
    tcp.{c,h}                RFC 793 / 9293 state machine
    ip.{c,h}                 IPv4 header build/parse + checksum
  io/
    af_packet.{c,h}          dev-only RX/TX over a real NIC
    dpdk.c                   real DPDK pump under -DWITH_DPDK=1;
                             stub returning -1 otherwise. Always
                             links into the spike test build.
  tests/
    test_crypto.c            crypto + TLS + TCP RFC vectors (38 tests)
    Makefile                 stand-alone test runner
```

## Why ChaCha20-Poly1305 (and not AES-GCM)

RFC 8446 mandates `TLS_CHACHA20_POLY1305_SHA256` as a baseline
cipher suite. Every modern browser supports it. Pure-C ChaCha20 is
~80 lines and runs at ~2 GB/s on x86 without intrinsics; AES-GCM done
right needs AES-NI plus PCLMULQDQ for GHASH, otherwise it's slow and
side-channel-vulnerable. We can add it later behind a feature flag if
we ever need a hardware-AES win.

## TLS 1.3 key schedule (sketch)

```
   PSK(0)                                     0(0)
       |                                         |
       v                                         v
HKDF-Extract = Early Secret                       |
       |                                         |
       +---> Derive-Secret(., "ext binder", "")  |
       |     -> binder_key                       |
       |                                         |
       +---> Derive-Secret(., "c e traffic", ClientHello)
       |     -> client_early_traffic_secret      |
       |                                         |
       +---> Derive-Secret(., "e exp master", ClientHello)
             -> early_exporter_master_secret    |
                                                |
       0 ---> HKDF-Extract = Handshake Secret <-+
                                                ECDHE
                  (...)
```

We'll implement HKDF-Expand-Label and Derive-Secret in
`tls/keysched.c` with the labels exactly as RFC 8446 §7.1 specifies.

## Why this won't run end-to-end in WSL

WSL2's network stack is a Hyper-V virtual switch. We don't have a real
NIC bindable to DPDK or AF_XDP. AF_PACKET works but only against the
WSL virtual interface, which means we can't actually DoS-test against
real link conditions. The crypto primitives and TLS message parsers
all run in pure userspace and are tested against RFC vectors in this
branch — those parts are real, here, and green. The packet path is
sketched but not wired to a live link.

## Realistic next steps if we ever ship this

1. Boot a Linux VM with a passthrough NIC, get DPDK bound, smoke-test
   AF_PACKET first then graduate to AF_XDP, then to DPDK PMD.
2. Get a single TCP connection, single HTTP request, no TLS. End to end.
3. Add retransmit + RTO. This is where the months go.
4. Wire TLS 1.3 server-side. Borrow real cert+key off disk. Pass
   curl --insecure first; pass a real browser second.
5. Add cert chain validation (RSA-PSS or ECDSA verify), AES-GCM with
   AES-NI, session resumption.

Do not ship any of this without third-party security review.

## Layered architecture: webserver as a module on a userspace stack

The long-term shape (still being built out):

```
[ NIC RX ] -> [ driver: epoll | io_uring | DPDK | AF_XDP ]
            -> [ TCP reassembly  (per-flow, fixed flow table) ]
            -> [ TLS decrypt     (in-place over reassembled record) ]
            -> [ HTTP request slice + jumptable lookup ]
            -> [ response: array of pw_iov_t pointing at static arena ]
            -> [ TLS encrypt     (scatter-gather seal, ONE ciphertext blob) ]
            -> [ TCP segmentation (slices into MSS-sized descriptors) ]
            -> [ NIC TX ]
```

Each box is **deterministic** and performs **no allocation** after
startup. Buffers are rented from per-worker pools (`crypto/pool.c`).

### Canonical descriptor: `pw_iov_t`

`userspace/iov.h` defines:

```c
typedef struct pw_iov {
    const uint8_t* base;
    size_t         len;
} pw_iov_t;
```

This is intentionally identical in shape to POSIX `struct iovec` so it
maps 1:1 onto:

- `writev(2)` / `sendmsg(2)` / `sendmsg(MSG_ZEROCOPY)`
- `io_uring` SQE iov entries
- DPDK `rte_mbuf` chained payloads (next pointer + segment length)
- AF_XDP TX descriptor batches

The webserver **stops owning bytes and starts owning plans**. A
response is an `pw_iov_t[]` of 3–6 fragments pointing into the
immutable `mprotect(PROT_READ)` arena: status line, headers, chrome
header, page body, chrome footer. Nothing is ever copied out of the
arena — it flows straight through TLS into the TX path.

### Streaming ChaCha20 + scatter-gather AEAD

To make the `_iov` path bit-identical to a contiguous seal we needed
ChaCha20 to handle fragments that don't end on 64-byte block
boundaries. `crypto/chacha20.{c,h}` exposes:

```c
chacha20_stream_init(&cs, key, nonce, initial_counter);
chacha20_stream_xor(&cs, in, out, len);  /* call repeatedly */
```

The context carries any unused tail of the last keystream block
forward, so a fragment ending mid-block does not waste keystream
bytes. Bulk middle blocks still go through the SIMD-dispatched path
(`chacha20_xor_fn`). The streaming primitive tests prove identity
against the one-shot path across an awkward fragmentation pattern
(fragments of 1, 7, 13, 64, 65, 100, 256, 511, 513, 1024, 1003).

`crypto/chacha20_poly1305.c` exposes:

```c
aead_chacha20_poly1305_seal_iov(key, nonce, aad, aad_len,
                                pt_iov, pt_iov_n, total_pt_len,
                                ct_out, tag);
```

It walks the iov chain, encrypting fragments via `chacha20_stream_xor`
into a contiguous ciphertext buffer, while feeding Poly1305
incrementally over the AAD || pad || ciphertext || pad || lens
sequence. The contiguous output is what the TX path then segments.

`tls/record.c` exposes:

```c
tls13_seal_record_iov(dir, inner_type, outer_type,
                      pt_iov, pt_iov_n, total_plaintext_len,
                      out, out_cap);
```

The total length is **known up front** (sum of `iov[].len`), so the
record header (5 bytes: type / version / length) is written before any
encryption work happens. This is the property the user wanted: "I want
to be able to pass an array of pointers and a feature to calculate the
length into the tcp layer before tls is hit." Length flows top-down,
bytes flow bottom-up, no copy required.

### Test coverage of the iov path

`userspace/tests/test_crypto.c` proves that:

1. `chacha20_stream_xor` over arbitrary fragmentation == one-shot
   `chacha20_xor` over the concatenation (4096 B random + edge cases).
2. `aead_chacha20_poly1305_seal_iov` produces byte-identical
   ciphertext + tag to `aead_chacha20_poly1305_seal` over the same
   plaintext, and `aead_chacha20_poly1305_open` recovers the original.
3. `tls13_seal_record_iov` produces a byte-identical wire record to
   `tls13_seal_record`, and `tls13_open_record` of the iov-sealed
   record recovers the original plaintext.

### Run-to-completion connection runtime (`userspace/conn.{c,h}`)

The `pw_conn_t` is a thin wrapper around `pw_tls_engine_t` for
callers that prefer the legacy "give me bytes, get sealed bytes
back" function-call shape over the engine's port-based state
machine. It embeds an engine and uses
`pw_tls_engine_install_app_keys` to skip the handshake (callers
that want a real TLS 1.3 handshake should drive the engine
directly via `pw_tls_engine_configure_server`).

```
pw_conn_rx(conn, in_bytes, in_len,
           response_fn, response_user,
           out_buf, out_cap, &out_len);
```

walks the diagram:

```
in bytes  -> pw_tls_rx_buf + ack
          -> pw_tls_step (engine opens at most ONE record into APP_IN)
          -> response_fn(APP_IN bytes) -> pw_response_t (iov chain)
          -> pw_tls_app_seal_iov (zero-copy scatter-gather AEAD into TX)
          -> drain TX -> sealed wire bytes for TCP segmentation
```

Status returns: `OK` (sealed bytes ready), `NEED_MORE` (record not
yet complete; feed more bytes), `AUTH_FAIL` (bad tag — close conn),
`PROTOCOL_ERR`, `RESPONSE_FAIL`, `OUT_OVERFLOW`. Tested end-to-end
with chunked arrival (2x NEED_MORE then OK), tampered ciphertext
(rejected with AUTH_FAIL), back-to-back records concatenated in a
single call (engine opens at most one per step; the second is
processed on the next call), and roundtrip plaintext equivalence.

The webserver-as-module decoupling is now real: `pw_response_fn` is
the only thing the runtime knows about the application. picoweb's
existing flat-table lookup + chrome/page/footer rendering plugs in
as a `pw_response_fn` whose `pw_iov_t[]` points straight at the
immutable `mprotect(PROT_READ)` arena.



- TLS 1.3 Certificate / CertificateVerify (Ed25519 sign) / Finished —
  wire builders complete: `tls13_build_certificate`,
  `tls13_build_certificate_verify` (Ed25519, RFC 8446 §4.4.3),
  `tls13_build_finished`. Engine integration — using these to drive
  the handshake instead of `install_app_keys` — is the next step.

## L4 pre-jump table (`userspace/dispatch.{c,h}`)

Right after iov was the load-bearing primitive for the data path,
**dispatch** is the load-bearing primitive for the control path.

The picoweb userspace stack is **multipurpose** — one TCP/UDP stack
hosting many independent services on different ports (HTTPS on 443,
plain HTTP on 80, gossip on 7777, DNS on 53, …). The dispatch table
is what makes that work without a per-service stack.

```c
typedef enum { PW_PROTO_TCP = 6, PW_PROTO_UDP = 17 } pw_proto_t;

typedef enum {
    PW_DISP_NO_OUTPUT, PW_DISP_OUTPUT, PW_DISP_OUTPUT_AND_CLOSE,
    PW_DISP_RESET, PW_DISP_ERROR,
} pw_disp_status_t;

typedef struct {
    pw_proto_t      proto;
    uint16_t        port;
    void*           svc_state;
    pw_on_open_fn   on_open;     // returns per-conn state, or NULL to refuse
    pw_on_data_fn   on_data;     // status + iov_out[0..iov_n) bytes to send
    pw_on_close_fn  on_close;    // called exactly once per successful on_open
} pw_service_t;

typedef struct {
    pw_service_t entries[PW_DISPATCH_MAX];   // packed array, N <= 16
    unsigned     n;
} pw_dispatch_t;
```

### Why a packed linear scan and not a hash table

`PW_DISPATCH_MAX` is 16. The entire array fits in one cache line, the
comparison is a `u16 == u16`, and the branch predictor wins easily for
small N. A hash with a separate bucket array would touch more cache
and pay an extra indirection for nothing. Built once at startup,
**immutable after attach** — matches the project's no-allocation-after-
startup invariant.

### Lifecycle contract (TCP)

The contract is small but strict, because the alternative is leaks or
double-frees:

- `on_open` is called **exactly once per connection**, **after** TCP
  reaches `ESTABLISHED`. Deliberately not at SYN: half-open
  connections must not consume scarce per-conn state, or a SYN flood
  trivially exhausts the service's pool. The hook returns a per-conn
  state pointer (typically rented from a fixed-size pool the service
  owns at startup) or `NULL` to refuse the connection (TCP layer
  emits RST and never calls `on_close` for the refused conn).
- `on_data` is called for each in-order data chunk. The service
  populates `iov_out[0..iov_max)` with `(ptr, len)` descriptors
  pointing at long-lived storage it owns, sets `*iov_n`, and returns
  one of `NO_OUTPUT / OUTPUT / OUTPUT_AND_CLOSE / RESET / ERROR`.
  TCP layer turns that into ACK / sendv / sendv+FIN / RST.
- `on_close` is called **exactly once for every successful `on_open`**
  (FIN, RST, app-initiated close). Never called if `on_open` refused.

The dispatch table itself is **immutable after attach** — stored
service pointers stay valid for the lifetime of the stack.

### Wiring into TCP

```c
int tcp_attach_dispatch(tcp_stack_t* s, uint32_t local_ip,
                        const pw_dispatch_t* d);
int tcp_sendv(tcp_conn_t* c, const pw_iov_t* iov, unsigned n,
              tcp_emit_fn emit, void* emit_user);
```

`tcp_input` looks up `(PW_PROTO_TCP, dst_port)` for inbound segments.
Unknown port → RST. Match → standard SYN/ACK handshake; on the final
ACK the conn transitions to `ESTABLISHED` and `on_open` fires.

The legacy single-port `tcp_listen` API still works (back-compat for
tests), but new code should use `tcp_attach_dispatch`.

### Test coverage of the dispatch path

`test_dispatch_table` (11 cases): register / lookup / duplicate
rejection / invalid `on_data` / port=0 rejection / cap.

`test_tcp_dispatch` (12 cases): unknown port → RST + no service
touched, on_open fires at ESTABLISHED (not SYN — proven by counter
inspection between SYN and final ACK), OUTPUT path delivers reply
bytes, OUTPUT_AND_CLOSE emits data + FIN, on_close fires exactly once
on LAST_ACK transition, pool exhaustion (3rd conn against a 2-slot
pool) → RST + no phantom on_close, `tcp_sendv` 2-fragment coalesce,
multi-service routing (port 443 → svc443, port 80 → svc80, no
crosstalk).

UDP support: API surface (`PW_PROTO_UDP`) is in place but `udp.c` is
not yet written. When it lands, the dispatch table is the same.

## TLS engine (`userspace/tls/engine.{c,h}`)

The original `pw_conn` runs a full RX→TLS-open→HTTP→TLS-seal→TX
pipeline as one call. That works for the in-tree dispatch demo, but
inverts control: the I/O loop has to *be* the loop. For io_uring,
DPDK, and any caller that wants its own scheduler, the right shape
is byte-level ports plus a `step` function that does no more work
than the current bytes allow.

`pw_tls_engine_t` is exactly that. The engine has four ports:

```
                   +------------------+
   ciphertext  --> |  RX buffer       |
   from socket     +--------+---------+
                            v
                   +------------------+        +-----------+
                   |  step(): try to  |        |  state:   |
                   |   open one record|----->  | HANDSHAKE |
                   |   try to seal one|        |    APP    |
                   +--------+---------+        |  CLOSED   |
                            ^                  |  FAILED   |
   plaintext   <-- +--------+---------+        +-----------+
   to handler      |  APP_IN buffer   |
                   +------------------+

                   +------------------+
   plaintext   --> |  APP_OUT buffer  |
   from handler    +--------+---------+
                            v   step()
                   +------------------+
   ciphertext  <-- |  TX buffer       |
   to socket       +------------------+
```

API (paraphrased):

```c
void  pw_tls_engine_init(pw_tls_engine_t*);
int   pw_tls_engine_install_app_keys(pw_tls_engine_t*, ...);
unsigned pw_tls_want(const pw_tls_engine_t*);   /* WANT_RX|WANT_TX|APP_IN_RDY|APP_OUT_OK */
pw_tls_state_t pw_tls_state(const pw_tls_engine_t*);

/* Transport side */
uint8_t* pw_tls_rx_buf(pw_tls_engine_t*, size_t* cap);
void     pw_tls_rx_ack(pw_tls_engine_t*, size_t n);
const uint8_t* pw_tls_tx_buf(const pw_tls_engine_t*, size_t* len);
void     pw_tls_tx_ack(pw_tls_engine_t*, size_t n);

/* App side */
const uint8_t* pw_tls_app_in_buf(const pw_tls_engine_t*, size_t* len);
void     pw_tls_app_in_ack(pw_tls_engine_t*, size_t n);
int      pw_tls_app_out_push(pw_tls_engine_t*, const pw_iov_t*, unsigned n);

/* Drive forward as far as current bytes allow. */
int   pw_tls_step(pw_tls_engine_t*);
void  pw_tls_close(pw_tls_engine_t*);

/* server-only: configure with a real RNG, ed25519 seed, cert chain.
 * Once configured, pw_tls_step drives a real CH -> SH -> install
 * handshake-traffic keys flow on its own. */
int   pw_tls_engine_configure_server(pw_tls_engine_t*, pw_tls_rng_fn,
                                     void* rng_user, const uint8_t seed[32],
                                     const uint8_t* chain_der,
                                     const size_t* cert_lens, unsigned n);
pw_tls_hs_phase_t pw_tls_hs_phase(const pw_tls_engine_t*);
```

The engine is the same architecture as `pw_conn`, just with the
loop inverted: caller drives `step` whenever bytes move.

`pw_tls_engine_install_app_keys` is a **spike-mode shortcut** that
jumps directly to APP state with caller-supplied symmetric keys.
It bypasses the handshake. With the server-side handshake driver
landed, this helper is now strictly for tests that want to exercise
APP-state behaviour without doing a full handshake.

`pw_tls_engine_configure_server` opts into the **real handshake
driver**. After this call, feeding a TLS 1.3 ClientHello into RX
and calling `pw_tls_step` will:
1. Parse the CH (and validate offers TLS 1.3, ChaCha20-Poly1305,
   X25519, Ed25519).
2. Generate `server_random` and the ECDHE ephemeral keypair via
   the caller's RNG (clamped per RFC 7748 §5).
3. Compute `X25519(eph_priv, ch.client_pub)` AND constant-time
   check it isn't all-zero (RFC 8446 §7.4.2 / RFC 7748 §6.1
   low-order-point defence). On all-zero, abort with state→FAILED
   **before** writing anything to TX — proven by the
   `no SH leaked on low-order share` test.
4. Build a ServerHello that echoes the client's
   `legacy_session_id` verbatim (browser compat-mode interop) and
   includes our X25519 pubkey.
5. Update the running transcript with CH and SH (handshake-msg
   bytes only — no record headers in the transcript).
6. Derive the handshake secrets via
   `tls13_compute_handshake_secrets(shared, transcript_hash, …)`.
7. Install client→server / server→client handshake-traffic keys
   into `eng->read` / `eng->write` and reset both `seq` to 0.
8. Wipe `eph_priv` and `shared`.
9. Emit the SH as a plaintext TLS record into TX.

State stays `HANDSHAKE`; an internal `hs_phase` walks
`WAIT_CH` → `AFTER_SH_KEYS` → `AFTER_SF_AWAIT_CF`. Within a single
`pw_tls_step()` call after the CH lands, the engine drives
`try_drive_handshake_server` (CH→SH+keys), then
`try_emit_server_flight` (encrypted EE / Cert / CV / sFin sealed
under the server handshake-traffic key, and application-traffic
secrets derived + cached), then sits in `AFTER_SF_AWAIT_CF` waiting
for the client Finished. Inbound dummy ChangeCipherSpec records
(RFC 8446 §D.4 compat-mode) are silently consumed in this phase.
Once the client Finished verifies, the engine swaps `read`/`write`
to application-traffic keys (both `seq` reset to 0), wipes all
handshake-phase secrets, and transitions to `APP`.

On any fatal handshake failure the engine wipes ALL key material
(handshake + installed record-layer keys) AND clears `tx_len`, so a
caller that reads `pw_tls_tx_buf` after a failure sees no bytes —
i.e. partial encrypted handshake records are never flushable.

**Want bits** are the only thing the I/O loop needs to look at:
- `WANT_RX`: room in the RX buffer; safe to `recv()`.
- `WANT_TX`: TX buffer has bytes; should be drained to the wire.
- `APP_IN_RDY`: plaintext is ready for the handler.
- `APP_OUT_OK`: room in APP_OUT; safe to push more plaintext.

In `HANDSHAKE` state APP_IN_RDY / APP_OUT_OK are masked off so
nobody pushes plaintext before keys exist (gated test:
`APP_OUT_OK NOT set in HANDSHAKE state`).

Buffer sizing: each engine carries 4 × `PW_TLS_BUF_CAP` (~66 KiB).
That's a lot per concurrent flow; the engine is designed to be
*rented* from a fixed pool of N engines, not allocated per flow
(see open items).

**Composition with dispatch.** The engine is what makes the killer
demo work: a `tls_echo` service registered on TCP/443 that decrypts
inbound bytes and seals the same bytes back out, all driven by
dispatch's `on_data` returning a `pw_iov_t` pointing at the
engine's TX buffer. Test
`test_engine_via_dispatch` does exactly this end-to-end through the
TCP state machine:

```
client engine  ──seal──> [TCP/443] ──> dispatch ──> tls_echo
                                                      │
                                       open + reseal  ▼
                              <── [TCP/443 reply] ──── server engine
                       open
client engine  ──────────────> "echo me!" ✓
```

149/149 tests covering: state transitions, want-bit gating,
two-iov push, multi-record sequence-number advance, tampered tag
→ FAILED, dispatch round-trip with on_open at ESTABLISHED and
on_close exactly once on FIN.

## Ed25519 (`userspace/crypto/ed25519.{c,h}`)

Pure-C Ed25519 sign / verify (RFC 8032), the signature half of the
TLS 1.3 handshake. Lets the engine compute its own
CertificateVerify and lets us drop the spike-mode
`install_app_keys` shortcut.

Layout (single C file, ~1100 lines, four numbered sections):

1. **Field arithmetic** over `GF(2^255 - 19)` with 5×51-bit limbs.
   Algorithmically identical to `x25519.c`; duplicated rather than
   shared because the Edwards code wants several extra primitives
   (`fe_neg`, `fe_pow22523`, `fe_isnegative`, `fe_iszero`) and we
   didn't want to grow X25519's surface area.
2. **Edwards group ops** in extended coordinates `(X:Y:Z:T)` with
   `T = X*Y/Z`. Hisil-Wong-Carter-Dawson formulas for `a = -1`.
   Doubling and (cached-form) addition only — no separate
   `ge_p2` / `ge_p1p1` types. The HWCD doubling output satisfies
   `X3*Y3 = T3*Z3` directly so we never lose the `T` invariant.
   `ge_p3_frombytes_vartime` rejects non-canonical `y` (reject
   `y_bytes >= p`) and the special case `(x = 0, sign-bit = 1)`.
   Strategic `fe_carry` calls in `ge_dbl` keep limbs bounded so
   the next `fe_sub` cannot underflow.
3. **Scalar arithmetic mod L** where
   `L = 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed`.
   `sc_reduce` (64 → 32 bytes) and `sc_muladd` (`s = a*b + c mod L`)
   in the standard 12 × 21-bit balanced-limb form. Reduction
   constants `{666643, 470296, 654183, -997805, 136657, -683901}`
   are `L_low` re-expressed in those limbs — mathematical facts
   derived from `L`, not third-party code.
4. **Public API**: `ed25519_pubkey_from_seed`, `ed25519_sign`
   (RFC 8032 §5.1.6), `ed25519_verify` (§5.1.7 non-cofactor).

```c
void ed25519_pubkey_from_seed(uint8_t pk[32], const uint8_t seed[32]);
void ed25519_sign(uint8_t sig[64], const uint8_t* msg, size_t len,
                  const uint8_t seed[32], const uint8_t pk[32]);
int  ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t len,
                    const uint8_t pk[32]);  /* 1 valid, 0 invalid */
```

Curve constants (`d`, `2d`, `sqrt(-1)`, base point `B`) are stored
as 32-byte little-endian arrays and decoded via `fe_from_bytes`
locally inside each call — no global init, no cache, no thread-
safety trap. The ~50 ns per decode is amortised across a scalar
mult.

Verify uses naïve double-scalar-mult (two separate scalar mults
summed). Slower than Strauss-Shamir, but the verify path isn't on
the hot loop for a TLS *server* — we sign far more than we verify.

**Spike-scope gaps documented in the file header**:
- Variable-time scalar mult in both sign and verify. Fine for the
  picoweb use case (server signs with its own cert) — *not* fine
  for production CT requirements.
- No small-order public-key rejection in `verify`. Justified by
  current threat model: the server signs with its own static cert
  and never verifies attacker-controlled public keys (no mTLS).
  Must be added before mTLS lands.

Tests (RFC 8032 §7.1 `TEST 1` / `TEST 2` / `TEST 3` plus negative
cases):
- `pubkey_from_seed` matches RFC for all three vectors.
- `sign(msg)` produces RFC-bit-identical signatures.
- `verify(sig)` accepts the RFC signatures.
- Sign-verify roundtrip on a 200-byte message.
- Bit-flips in `sig`, `pk`, and `msg` are all rejected.
- A non-canonical `R` (`y_bytes == p` exactly) is rejected
  by point decode.

170/170 total tests on `main`.

### CertificateVerify (RFC 8446 §4.4.3)

`tls13_build_certificate_verify` produces the 72-byte wire CV
message for an Ed25519 server cert. It builds the 130-byte signed
prefix (64 × 0x20 padding || ASCII context label || 0x00 ||
transcript hash), feeds it to `ed25519_sign`, and emits:

```
0x0f  body_len_u24=68              ; handshake header
0x0807                              ; SignatureScheme = ed25519
0x0040                              ; sig length = 64
[64-byte Ed25519 signature]
```

`cert_extract_ed25519_seed(entry, out)` walks the PKCS#8
PrivateKeyInfo (`SEQUENCE { INTEGER 0, alg-OID-Ed25519,
OCTET STRING wrapping CurvePrivateKey }`) and returns the 32-byte
seed. Tiny inline DER walker in `cert.c`; long-form lengths
explicitly rejected (Ed25519 keys are always short-form).

The signed prefix is also exposed via
`tls13_build_certificate_verify_signed_data` so tests (and a
future verify path for mTLS) can construct it directly.

## <a id="open-engineering-items"></a>Open engineering items

This is the running TODO for what's blocking real-traffic readiness.

- **Engine error code** ✅ DONE. `pw_tls_engine_t` now carries a
  `pw_tls_err_t last_err` set on transition to `PW_TLS_ST_FAILED`,
  exposed via `pw_tls_last_error()`. Five classes:
  `NONE / AUTH / PROTOCOL / OVERFLOW / INTERNAL`. `pw_conn` fans out:
  `AUTH` -> `PW_CONN_AUTH_FAIL`, all other classes ->
  `PW_CONN_PROTOCOL_ERR`, restoring the pre-migration distinction.
- **Receive-window-driven backpressure** on the TCP layer ✅ DONE.
  `tcp_conn_t` carries `rcv_buf_cap` / `rcv_buf_used`;
  `tcp_advertised_wnd()` reports the live window, `emit_ctrl()`
  recomputes on every outbound. Persist probes are dropped without
  advancing `rcv_nxt` and re-ACKed with the (still 0) window.
  `tcp_rcv_consumed()` emits a window-update ACK on 0 -> non-zero.
- **TCP retransmit + RTO** ✅ DONE. Per-conn `tcp_rtx_entry_t[]`
  retransmit queue (cap `TCP_RTX_QUEUE_MAX`, zero-copy contract on
  payload pointers); RFC 6298 SRTT/RTTVAR/RTO estimator (alpha=1/8,
  beta=1/4, K=4, RTO clamped to `[TCP_RTO_MIN_MS, TCP_RTO_MAX_MS]`,
  initial `TCP_RTO_INIT_MS=1000`); `tcp_tick(now_ms)` retransmits
  oldest unacked when `(now - tx_time) >= rto`, doubles RTO; Karn's
  algorithm skips RTT samples on retransmitted segments. No
  congestion control yet (no slow-start, cwnd, fast retransmit).
- **mbuf class for reassembly** ✅ DONE. `PW_TLS_WIRE_RECORD_MAX` /
  `PW_RX_REASSEMBLY_SLOT` in `tls/record.h` (16661 bytes = header +
  max ciphertext); recommended pool slab `slot_size` documented in
  `crypto/pool.h`.
- **Real driver integration:** the `pw_iov_t` array on TX is ready to
  feed `writev` / `io_uring_prep_writev` / `rte_mbuf` chains; the
  abstraction is sketched but not wired to a live link.
- **Per-conn state rental from the buffer pool** when the service has
  many concurrent flows (today services own their own fixed pool;
  shared rental would let many low-traffic services share a single
  budget).
- **Constant-time scalar mult** in Ed25519 (currently variable-time;
  prerequisite for production cert-signing in adversarial latency
  contexts). NOT in current scope (mTLS prerequisite, deferred).
- **Small-order public-key rejection** in `ed25519_verify`
  (prerequisite for mTLS). NOT in current scope (deferred).
