# picoweb userspace TCP + TLS — design spike

> **Status: spike branch (`spike/userspace-tcp-tls`).** This is a
> design + foundation spike, not a production stack. The work to ship
> a real userspace TCP+TLS network path is months of engineering. The
> purpose of this branch is to map the work, lay down the crypto
> primitives, sketch the handshake and TCP state machines, and be
> honest about what is and isn't done.
>
> **What is real, here, and green (38 RFC-vector tests passing):**
> SHA-256, HMAC-SHA256, HKDF-SHA256, ChaCha20, Poly1305,
> ChaCha20-Poly1305 AEAD, X25519 ECDH, TLS 1.3 HKDF-Expand-Label and
> Derive-Secret (RFC 8448 §3 vectors), TLS 1.3 record seal/open with
> sequence-number nonce, IPv4 + TCP header build/parse with both
> IPv4 and TCP checksums, TCP passive-open state machine
> (LISTEN → SYN-RECEIVED → ESTABLISHED → CLOSE-WAIT → LAST-ACK).
>
> **What is sketched but not wired:** AF_PACKET I/O (compiles on
> Linux, no E2E test), DPDK loop pattern (commented sketch only).
>
> **What is deliberately not in scope:** TLS 1.3 handshake message
> parsing (ClientHello / ServerHello), ECDSA / RSA cert signing,
> AES-GCM, TCP retransmit / RTO / congestion control / SACK, SYN
> cookies, fuzz testing of parsers. All called out in §"Scope" below.

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
5. A **DPDK** sketch that documents the rte_eal_init / port setup /
   rx/tx burst pattern. Doesn't run in WSL (no PMD-bindable NICs);
   present as code for later. **Status:** comment-only, never built.

What is **explicitly NOT** in this branch:

- AES-GCM (we have ChaCha20-Poly1305; that's enough for TLS 1.3
  interop — RFC 8446 mandates it as a mandatory cipher suite).
- Ed25519 / RSA. We have ECDHE via X25519. Server cert verification
  is on the client side; we'd only need to *sign* if we were the
  server, and even then we can use externally-generated certs read
  off disk and signed at provisioning time.
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
    dpdk_sketch.c            commented sketch, won't build without RTE
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
