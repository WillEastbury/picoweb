# TLS backend — design

> **Status:** design + scaffold. The aarch64 userspace crypto build
> blocker is fixed (commit `4c0febb` — `sha256_compress_armv8`) and
> the userspace TLS+TCP stack is fully green (285/285 vectors). This
> doc + the accompanying `src/tls_bridge.{h,c}`, `src/server_tls.c`
> and main.c flag wiring lay the foundation for a `--tls` backend.
> The end-to-end runtime path (real NIC, real handshake) is not yet
> live — see "What's NOT done yet" below.

## Goal

Add a fourth picoweb backend selectable at runtime:

```
./picoweb [--io_uring | --dpdk | --tls] [...]
./picoweb --tls --tls-cert=cert.pem --tls-key=key.pem \
          --tls-ifname=eth0 [--tls-peer-mac=AA:BB:CC:DD:EE:FF] \
          [443] [wwwroot] [WORKERS] [...]
```

The `--tls` backend serves HTTPS *without using the kernel's TCP
stack at all* — packets flow directly from a NIC to userspace via
AF_PACKET (initially) or AF_XDP (future), get parsed by the
userspace TCP state machine (`userspace/tcp/`), decrypted by the
userspace TLS 1.3 engine (`userspace/tls/`), and the resulting
plaintext is dispatched into the existing HTTP jumptable
(`src/jumptable.c` + `src/http.c`) for response building.

## Why this shape

picoweb already has two relevant assets:

1. A mature, test-covered userspace TCP+TLS+crypto spike under
   `userspace/` — 285 RFC vectors green, including TLS 1.3 RFC 8448
   §3 vectors, full PSK + 0-RTT, scatter-gather AEAD seal, and a
   passive-open TCP state machine with NewReno + RTO + IW10.
2. A blazing-fast HTTP request path under `src/` with a flat-buffer
   jumptable, zero-copy chrome, brotli, NUMA-aware arena, etc.

Until now these have lived in parallel. The `--tls` backend stitches
them: TCP+TLS terminate inbound traffic, the dispatch shim hands
plaintext HTTP bytes to the existing jumptable, and the response
goes back through TLS+TCP+AF_PACKET. No kernel TCP touched.

Doing it this way buys us:

- **Zero kernel-TCP overhead** on the data path (one fewer copy per
  byte; no socket-layer locking; no `tcp_input` from the kernel).
- **Drop-in path to AF_XDP**: swapping `userspace/io/af_packet.c` for
  `userspace/io/af_xdp.c` becomes a backend-only change.
- **One process, one binary** still — no DPDK-style EAL, no setuid
  helper, no separate dataplane.

## Packet flow (RX)

```
 NIC
  │  raw Ethernet frame
  ▼
 AF_PACKET socket  (userspace/io/af_packet.c)
  │  ETH_HDR_LEN-stripped IPv4 packet
  ▼
 ip_parse          (userspace/tcp/ip.c)
  │  tcp_seg_t (raw TCP segment + IPv4 src/dst)
  ▼
 tcp_input         (userspace/tcp/tcp.c)
  │  routes by (PROTO, dst_port) via dispatch table
  ▼
 tls_bridge::on_data   (src/tls_bridge.c)  ← NEW
  │  ciphertext bytes pushed into pw_tls_engine.rx_buf
  ▼
 pw_tls_step       (userspace/tls/engine.c)
  │  decrypts, runs handshake state machine
  ▼
 tls_bridge::on_data drains pw_tls_app_in_buf
  │  HTTP request bytes (plaintext)
  ▼
 http_parse        (src/http.c)        — existing
  │  parsed_request_t
  ▼
 jumptable_lookup  (src/jumptable.c)   — existing
  │  resource_t + variant selection
  ▼
 build response (head + body iovec)
```

## Packet flow (TX)

```
 response iovecs (head + body)
  │  HTTP plaintext bytes
  ▼
 pw_tls_app_out_push   (userspace/tls/engine.c)
  │  + pw_tls_step seals into TLS records
  ▼
 tls_bridge::on_data drains pw_tls_tx_buf
  │  TLS ciphertext bytes
  ▼
 dispatch returns PW_DISP_OUTPUT with iov_out = {tls_tx, n}
  │
  ▼
 tcp_send + tcp_emit_fn   (userspace/tcp/tcp.c)
  │  prepends IPv4+TCP headers
  ▼
 af_packet_send_ipv4      (userspace/io/af_packet.c)
  │  prepends Ethernet header
  ▼
 NIC
```

## State model

Per accepted TCP connection we hold:

| Field        | Owner                        | Lifetime              |
|--------------|------------------------------|-----------------------|
| `tcp_conn_t` | `userspace/tcp/`'s table     | SYN-RCVD → CLOSED     |
| `pw_tls_engine_t` | `pw_tls_engine_pool_t`  | rented at TCP open, returned at close |
| `tls_bridge_state_t` (new) | per-conn arena slot | ditto                 |

The engine pool is sized to `TCP_TABLE_SIZE` (currently 8 in the
spike — small for testing; production would size both higher). The
bridge state is allocated from a fixed-cap pool to preserve the
zero-allocation-after-startup invariant.

## Dispatch wiring

The userspace stack already has a generic L4 jumptable (`pw_dispatch_t`
in `userspace/dispatch.h`). The TLS backend registers a single
service:

```c
pw_service_t https = {
    .proto    = PW_PROTO_TCP,
    .port     = 443,
    .svc_state = &g_tls_bridge,    /* shared bridge config */
    .on_open  = tls_bridge_on_open,
    .on_data  = tls_bridge_on_data,
    .on_close = tls_bridge_on_close,
};
pw_dispatch_register(&disp, &https);
tcp_attach_dispatch(&stack, local_ip, &disp);
```

The bridge's `on_data` is the heart of the integration:

```c
pw_disp_status_t tls_bridge_on_data(void* per_conn, const uint8_t* data,
                                    size_t len, pw_iov_t* iov_out,
                                    unsigned iov_max, unsigned* iov_n) {
    tls_bridge_state_t* st = per_conn;
    pw_tls_engine_t*    eng = st->engine;

    /* 1. push inbound ciphertext into the engine */
    push_into_engine(eng, data, len);

    /* 2. drive */
    pw_tls_step(eng);

    /* 3. drain decrypted plaintext, run HTTP, build response */
    plain = pw_tls_app_in_buf(eng, &plen);
    if (plen > 0) {
        run_http_pipeline(st, plain, plen);
        pw_tls_app_in_ack(eng, plen);
    }

    /* 4. push HTTP response (if any) into the engine to be sealed */
    if (st->resp_len > 0) {
        pw_tls_app_out_push(eng, st->resp_buf, st->resp_len);
        pw_tls_step(eng);
        st->resp_len = 0;
    }

    /* 5. drain ciphertext into the dispatch's iovec */
    tx = pw_tls_tx_buf(eng, &tlen);
    if (tlen > 0) {
        iov_out[0] = (pw_iov_t){tx, tlen};
        *iov_n     = 1;
        pw_tls_tx_ack(eng, tlen);
        return st->close_after ? PW_DISP_OUTPUT_AND_CLOSE
                               : PW_DISP_OUTPUT;
    }
    return PW_DISP_NO_OUTPUT;
}
```

Subtleties handled in the real implementation (not the sketch):

- **Handshake pacing**: the first few `on_data`s only produce
  handshake records — no `app_in` yet. The bridge must keep
  draining `tx_buf` across calls without ever consulting HTTP.
- **Response straddling records**: a single HTTP response may not
  fit in `app_out_buf` in one push; the bridge holds residual
  bytes and calls `pw_tls_app_out_push` again next round-trip.
- **Half-close**: HTTP's `Connection: close` maps to setting
  `st->close_after`; we need a clean TLS close_notify followed by
  TCP FIN.

## Cert + key loading

Resolution order (first match wins, all paths checked at startup):

1. **Explicit CLI flags** — `--tls-cert=PATH --tls-key=PATH`
   (must be specified together; either alone is a startup error).
2. **Kubernetes / cert-manager mount** — `/certs/tls.crt` +
   `/certs/tls.key`. This is the canonical layout for a
   cert-manager-managed `kubernetes.io/tls` Secret mounted into
   the pod (e.g. Secret `wfl-www-tls`):

   ```yaml
   volumeMounts:
     - name: tls
       mountPath: /certs
       readOnly: true
   volumes:
     - name: tls
       secret:
         secretName: wfl-www-tls   # has keys tls.crt + tls.key
   ```

3. **Local dev mount** — `./certs/tls.crt` + `./certs/tls.key`
   (cwd-relative). Symmetric with the k8s layout so a local
   developer can `mkdir certs && cp dev.crt certs/tls.crt &&
   cp dev.key certs/tls.key && ./picoweb --tls`.

4. Otherwise: startup error with the exact paths attempted, e.g.

   ```
   picoweb: --tls requires a certificate. Searched (in order):
     --tls-cert / --tls-key (not given)
     /certs/tls.crt + /certs/tls.key (not present)
     ./certs/tls.crt + ./certs/tls.key (not present)
   ```

The chosen pair is mmap'd read-only, parsed via
`pem_decode_chain()` and `pem_decode()` from `userspace/tls/pem.c`.
Required formats:

- **Cert** (`tls.crt`): PEM, `-----BEGIN CERTIFICATE-----`, may be
  a chain (server cert first, then intermediates). Stored as
  concatenated DER + per-cert lens array, both lifetime-tied to
  the process.
- **Key** (`tls.key`): PEM, **Ed25519 PKCS#8**
  (`-----BEGIN PRIVATE KEY-----`). TLS 1.3 in this stack ships
  with Ed25519 signatures only — ECDSA/RSA are not in the engine
  yet. Mismatched key type fails with a clear error at startup,
  not at handshake time.

For cert-manager rotation: the kubelet replaces the mounted files
in-place when the Secret rotates. The first iteration of the TLS
backend will NOT pick up rotated certs (cert is mmap'd at startup
and held for process lifetime). A future revision can either:

- inotify-watch `/certs/` and reload via `pw_tls_engine_pool` swap,
  or
- rely on the standard k8s deployment pattern of triggering a
  rolling restart on Secret update.

The latter is simpler, stays inside the project's "build once at
startup" invariant, and is what we'll document for now.

## NIC binding

`--tls-ifname=eth0` is mandatory. We resolve the local MAC via
`ioctl(SIOCGIFHWADDR)` and the local IPv4 via `getifaddrs`. The
peer (gateway) MAC is harder — for the initial spike we accept
`--tls-peer-mac=AA:BB:CC:DD:EE:FF` and emit all replies to that
MAC. Real ARP/NDP resolution is deferred (it would live in
`userspace/tcp/arp.c`, doesn't exist yet).

## Constraints & honest limits

- **Requires CAP_NET_RAW** (or root) to open the AF_PACKET socket.
- **Won't run inside this dev container**: no NIC, seccomp blocks
  AF_PACKET. Same situation as the io_uring backend — we ship the
  code and rely on `test_tls_active.sh` to verify on the prod box.
- **TCP table size 8** in the spike: the existing `TCP_TABLE_SIZE`
  is intentionally small for unit-testability. To go beyond a
  toy load, bump that constant and the engine pool capacity.
- **No retransmit timer thread yet**: the userspace TCP has the RTO
  state but we don't yet have a thread driving `tcp_tick(now_ms)`
  — this is a TODO for the production wire-up.
- **No close_notify yet**: TLS half-close on HTTP `Connection: close`
  needs a small extension to the engine (close path returns 0
  pending app_out today).
- **No SNI cert switching**: one cert chain per process. The engine
  has SNI parser plumbing but the bridge picks a single chain
  configured at startup.

## What's NOT done yet (post this commit)

| Status | Item |
|--------|------|
| ✅ done | Design doc (this file) |
| ✅ done | aarch64 SHA-256 HW path (`sha256_armv8.c`) |
| ✅ done | 285/285 userspace TLS+crypto vectors green |
| 🚧 sketch | `src/tls_bridge.{h,c}` — dispatch shim |
| 🚧 sketch | `src/server_tls.c` — backend main-loop skeleton |
| 🚧 flags | `--tls`, `--tls-cert`, `--tls-key`, `--tls-ifname`, `--tls-peer-mac` parsed in main.c |
| ❌ todo | Cert chain + key actually loaded and handed to engine |
| ❌ todo | NIC MAC + local IP resolved via ioctl/getifaddrs |
| ❌ todo | Main loop drives `af_packet_recv` → `tcp_input` → bridge |
| ❌ todo | RTO timer thread / `tcp_tick` driver |
| ❌ todo | `test_tls_active.sh` — production verification |
| ❌ todo | Pull userspace sources into main Makefile (currently userspace builds standalone) |
| ❌ todo | AF_XDP I/O backend (separate, follows once XDP spike begins) |

## Test strategy

Two layers, mirroring `test_uring.sh` + `test_uring_active.sh`:

1. **`test_tls.sh`** — functional smoke. Starts the backend on a
   loopback-attached interface (or a network namespace + veth pair),
   `curl -k https://127.0.0.1/` and asserts 200 + correct headers.
   In CI without raw sockets it SKIPs.

2. **`test_tls_active.sh`** — production verification. Asserts in
   `/proc/<pid>/fd/*` that the process holds a `socket:[…]` of type
   AF_PACKET (gold-standard "we really are bypassing kernel TCP"),
   asserts no incoming TCP-establish traffic shows up via `ss -tn`
   on the bound port (proof we're handling SYN ourselves), and
   asserts a curl request actually completes a TLS handshake.

Both SKIP cleanly when AF_PACKET is unavailable (CAP-restricted
container, BSD/macOS).

## Future work pointers

- AF_XDP I/O backend — `userspace/io/af_xdp.c`, see XDP design notes
  in plan.md. Drops in under the same `tcp_input` path; bridge code
  unchanged.
- ECDSA P-256 + RSA signature paths in TLS engine, for cert
  compatibility with the broader internet.
- ARP/NDP in `userspace/tcp/arp.c` so `--tls-peer-mac` becomes
  optional.
- BBR or Cubic instead of NewReno (the loss-recovery path is the
  bigger win at internet RTT).
