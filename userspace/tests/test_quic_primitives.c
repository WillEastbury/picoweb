/*
 * Tests for picoweb userspace QUIC building blocks:
 *   - UDP/IPv4 framing (userspace/udp/udp.c)
 *   - AES-128 ECB (userspace/crypto/aes.c)
 *   - AES-128-GCM AEAD (userspace/crypto/aes_gcm.c)
 *
 * Vectors are sourced from FIPS-197, NIST GCM-Test-Vectors-AES, and
 * RFC 9001 Appendix A. Failure here = wire-format incompatibility:
 * DO NOT adjust the vectors, fix the implementation.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../udp/udp.h"
#include "../crypto/aes.h"
#include "../crypto/aes_gcm.h"
#include "../quic/varint.h"
#include "../quic/initial.h"
#include "../quic/packet.h"
#include "../quic/frames.h"
#include "../quic/loss.h"
#include "../quic/cc.h"
#include "../quic/flow.h"
#include "../quic/special.h"
#include "../quic/transport_params.h"
#include "../quic/crypto_stream.h"
#include "../quic/stream.h"
#include "../h3/h3.h"
#include "../qpack/qpack.h"
#include "../quic/keys.h"
#include "../quic/tls_ext.h"
#include "../quic/conn.h"

static int g_pass = 0;
static int g_fail = 0;

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t unhex(const char* hex, uint8_t* out, size_t out_cap) {
    size_t n = 0;
    while (hex[0] && hex[1] && n < out_cap) {
        if (hex[0] == ' ' || hex[0] == '\n' || hex[0] == ':') { hex++; continue; }
        int hi = hex_nibble(hex[0]); int lo = hex_nibble(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

static void check_eq(const char* name, const uint8_t* got, const uint8_t* want, size_t len) {
    if (memcmp(got, want, len) == 0) {
        printf("  PASS: %s\n", name);
        g_pass++;
    } else {
        printf("  FAIL: %s\n", name);
        printf("    got:  "); for (size_t i = 0; i < len; i++) printf("%02x", got[i]);  printf("\n");
        printf("    want: "); for (size_t i = 0; i < len; i++) printf("%02x", want[i]); printf("\n");
        g_fail++;
    }
}

static void check_int(const char* name, long got, long want) {
    if (got == want) { printf("  PASS: %s\n", name); g_pass++; }
    else { printf("  FAIL: %s (got %ld want %ld)\n", name, got, want); g_fail++; }
}

/* ============================================================== */
/* UDP framing                                                    */
/* ============================================================== */

static void test_udp_build_parse_roundtrip(void) {
    printf("== UDP framing: build/parse round-trip ==\n");
    uint8_t payload[] = {'H','e','l','l','o',',',' ','Q','U','I','C','!'};
    udp_dgram_t in = {
        .src_ip = 0x0a000001u,   /* 10.0.0.1 */
        .dst_ip = 0xc0a80164u,   /* 192.168.1.100 */
        .src_port = 443,
        .dst_port = 51234,
        .payload = payload,
        .payload_len = sizeof payload,
    };
    uint8_t buf[128];
    size_t n = ip_udp_build(buf, sizeof buf, &in);
    check_int("build returns 20+8+payload",
              (long)n, (long)(20 + 8 + sizeof payload));

    udp_dgram_t out;
    int rc = ip_udp_parse(buf, n, &out);
    check_int("parse returns 0", rc, 0);
    check_int("src_ip preserved",   (long)out.src_ip,   (long)in.src_ip);
    check_int("dst_ip preserved",   (long)out.dst_ip,   (long)in.dst_ip);
    check_int("src_port preserved", (long)out.src_port, (long)in.src_port);
    check_int("dst_port preserved", (long)out.dst_port, (long)in.dst_port);
    check_int("payload_len preserved",
              (long)out.payload_len, (long)in.payload_len);
    check_eq("payload bytes preserved", out.payload, payload, sizeof payload);
}

static void test_udp_zero_payload(void) {
    printf("== UDP framing: zero-length payload ==\n");
    udp_dgram_t in = {
        .src_ip = 1, .dst_ip = 2,
        .src_port = 53, .dst_port = 53,
        .payload = NULL, .payload_len = 0,
    };
    uint8_t buf[64];
    size_t n = ip_udp_build(buf, sizeof buf, &in);
    check_int("zero payload builds to 28", (long)n, 28);
    udp_dgram_t out;
    int rc = ip_udp_parse(buf, n, &out);
    check_int("zero payload parses", rc, 0);
    check_int("zero payload_len", (long)out.payload_len, 0);
}

static void test_udp_overflow_buffer(void) {
    printf("== UDP framing: tiny dst buffer ==\n");
    udp_dgram_t in = { .payload_len = 100 };
    uint8_t buf[20];
    size_t n = ip_udp_build(buf, sizeof buf, &in);
    check_int("build refuses oversize", (long)n, 0);
}

static void test_udp_parse_rejects_bad_proto(void) {
    printf("== UDP framing: rejects non-UDP proto ==\n");
    /* Build a TCP-shaped IP packet by hand. */
    uint8_t f[28] = {0};
    f[0] = 0x45; f[2] = 0; f[3] = 28; /* total len */
    f[8] = 64; f[9] = 6; /* TCP */
    /* Patch IPv4 csum (real one). */
    extern uint16_t inet_csum(const uint8_t*, size_t);
    uint16_t cs = inet_csum(f, 20);
    f[10] = cs >> 8; f[11] = cs & 0xff;
    udp_dgram_t out;
    int rc = ip_udp_parse(f, sizeof f, &out);
    check_int("non-UDP rejected", rc, -1);
}

static void test_udp_parse_rejects_bad_ip_csum(void) {
    printf("== UDP framing: rejects bad IPv4 csum ==\n");
    udp_dgram_t in = { .src_ip = 1, .dst_ip = 2, .src_port = 1, .dst_port = 2 };
    uint8_t buf[64];
    size_t n = ip_udp_build(buf, sizeof buf, &in);
    buf[10] ^= 0x01;          /* corrupt IP csum */
    udp_dgram_t out;
    int rc = ip_udp_parse(buf, n, &out);
    check_int("bad IP csum rejected", rc, -1);
}

static void test_udp_parse_rejects_bad_udp_csum(void) {
    printf("== UDP framing: rejects bad UDP csum ==\n");
    uint8_t payload[] = {1,2,3,4};
    udp_dgram_t in = { .src_ip = 1, .dst_ip = 2,
                       .src_port = 1, .dst_port = 2,
                       .payload = payload, .payload_len = sizeof payload };
    uint8_t buf[64];
    size_t n = ip_udp_build(buf, sizeof buf, &in);
    /* Flip a payload byte (after build, so UDP csum no longer matches) */
    buf[20 + 8 + 0] ^= 0xff;
    udp_dgram_t out;
    int rc = ip_udp_parse(buf, n, &out);
    check_int("bad UDP csum rejected", rc, -1);
    rc = ip_udp_parse_ex(buf, n, &out, 1 /* skip csum */);
    check_int("skip_csum bypasses check", rc, 0);
}

static void test_udp_parse_rejects_zero_csum(void) {
    printf("== UDP framing: zero-csum field is accepted (RFC 768) ==\n");
    uint8_t payload[] = {0xaa};
    udp_dgram_t in = { .src_ip = 1, .dst_ip = 2,
                       .src_port = 1, .dst_port = 2,
                       .payload = payload, .payload_len = 1 };
    uint8_t buf[64];
    size_t n = ip_udp_build(buf, sizeof buf, &in);
    /* Force csum field to zero on the wire (legal for IPv4 sender,
     * receiver MUST accept). */
    buf[20 + 6] = 0; buf[20 + 7] = 0;
    udp_dgram_t out;
    int rc = ip_udp_parse(buf, n, &out);
    check_int("wire csum=0 accepted", rc, 0);
}

static void test_udp_csum_never_zero(void) {
    printf("== UDP framing: csum is rewritten 0->0xffff per RFC 768 ==\n");
    /* Find a payload whose computed csum is zero. Brute-force a tiny
     * search: most random inputs work, but to keep the test
     * deterministic, just verify that built csum field is never 0. */
    for (int i = 0; i < 256; i++) {
        uint8_t payload[1] = { (uint8_t)i };
        udp_dgram_t in = { .src_ip = 0x01020304, .dst_ip = 0x05060708,
                           .src_port = 1234, .dst_port = 4321,
                           .payload = payload, .payload_len = 1 };
        uint8_t buf[64];
        size_t n = ip_udp_build(buf, sizeof buf, &in);
        if (n == 0) { printf("  FAIL: build at i=%d\n", i); g_fail++; return; }
        uint16_t cs = ((uint16_t)buf[20+6] << 8) | buf[20+7];
        if (cs == 0) {
            printf("  FAIL: built UDP csum was zero at i=%d\n", i);
            g_fail++; return;
        }
    }
    printf("  PASS: built UDP csum never zero across 256 payloads\n");
    g_pass++;
}

/* ============================================================== */
/* AES-128 ECB — FIPS-197 Appendix B / C.1                        */
/* ============================================================== */

static void test_aes128_fips197_appendix_b(void) {
    printf("== AES-128: FIPS-197 Appendix B vector ==\n");
    /* PT = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
     * KEY = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
     * CT = 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32 */
    uint8_t key[16], pt[16], expect[16], got[16];
    unhex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    unhex("3243f6a8885a308d313198a2e0370734", pt,  16);
    unhex("3925841d02dc09fbdc118597196a0b32", expect, 16);
    aes128_ctx_t ctx;
    aes128_init(&ctx, key);
    aes128_encrypt_block(&ctx, pt, got);
    check_eq("Appendix B encrypt", got, expect, 16);
}

static void test_aes128_fips197_appendix_c1(void) {
    printf("== AES-128: FIPS-197 Appendix C.1 vector ==\n");
    /* PT = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
     * KEY = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     * CT = 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a */
    uint8_t key[16], pt[16], expect[16], got[16];
    unhex("000102030405060708090a0b0c0d0e0f", key, 16);
    unhex("00112233445566778899aabbccddeeff", pt, 16);
    unhex("69c4e0d86a7b0430d8cdb78070b4c55a", expect, 16);
    aes128_ctx_t ctx;
    aes128_init(&ctx, key);
    aes128_encrypt_block(&ctx, pt, got);
    check_eq("Appendix C.1 encrypt", got, expect, 16);
}

/* ============================================================== */
/* AES-128-GCM — NIST gcmEncryptExtIV128 vectors                  */
/* ============================================================== */

static void run_gcm_case(const char* name,
                         const char* key_hex,
                         const char* iv_hex,
                         const char* aad_hex,
                         const char* pt_hex,
                         const char* ct_hex,
                         const char* tag_hex) {
    uint8_t key[16], iv[12];
    uint8_t aad[256], pt[256], expect_ct[256], expect_tag[16];
    size_t aad_n = unhex(aad_hex, aad, sizeof aad);
    size_t pt_n  = unhex(pt_hex,  pt,  sizeof pt);
    size_t ct_n  = unhex(ct_hex,  expect_ct, sizeof expect_ct);
    size_t tag_n = unhex(tag_hex, expect_tag, sizeof expect_tag);
    (void)tag_n;
    unhex(key_hex, key, 16);
    unhex(iv_hex,  iv,  12);

    uint8_t got_ct[256], got_tag[16];
    aes128_gcm_seal(key, iv,
                    aad, aad_n,
                    pt,  pt_n,
                    got_ct, got_tag);
    check_int("ct len matches", (long)ct_n, (long)pt_n);
    if (pt_n) check_eq(name, got_ct, expect_ct, pt_n);
    check_eq(name /* tag */, got_tag, expect_tag, 16);

    /* Round-trip open. */
    uint8_t recovered[256];
    int rc = aes128_gcm_open(key, iv,
                             aad, aad_n,
                             got_ct, pt_n,
                             got_tag,
                             recovered);
    check_int("open returns 0", rc, 0);
    if (pt_n) check_eq("open recovers plaintext", recovered, pt, pt_n);

    /* Tag tamper -> open MUST fail. */
    got_tag[0] ^= 0x01;
    rc = aes128_gcm_open(key, iv,
                         aad, aad_n,
                         got_ct, pt_n,
                         got_tag,
                         recovered);
    check_int("open rejects tampered tag", rc, -1);
}

static void test_aes128_gcm_nist(void) {
    printf("== AES-128-GCM: NIST CAVS vectors ==\n");
    /* Source: NIST CAVS gcmEncryptExtIV128.rsp,
     * [Keylen=128 IVlen=96 PTlen=0 AADlen=0 Taglen=128] Count=0 */
    run_gcm_case("nist#1 empty/empty",
        "11754cd72aec309bf52f7687212e8957",
        "3c819d9a9bed087615030b65",
        "",
        "",
        "",
        "250327c674aaf477aef2675748cf6971");

    /* [Keylen=128 IVlen=96 PTlen=128 AADlen=0 Taglen=128] Count=0 */
    run_gcm_case("nist#2 pt=128 aad=0",
        "7fddb57453c241d03efbed3ac44e371c",
        "ee283a3fc75575e33efd4887",
        "",
        "d5de42b461646c255c87bd2962d3b9a2",
        "2ccda4a5415cb91e135c2a0f78c9b2fd",
        "b36d1df9b9d5e596f83e8b7f52971cb3");

    /* [Keylen=128 IVlen=96 PTlen=128 AADlen=128 Taglen=128] Count=0 */
    run_gcm_case("nist#3 pt=128 aad=128",
        "c939cc13397c1d37de6ae0e1cb7c423c",
        "b3d8cc017cbb89b39e0f67e2",
        "24825602bd12a984e0092d3e448eda5f",
        "c3b3c41f113a31b73d9a5cd432103069",
        "93fe7d9e9bfd10348a5606e5cafa7354",
        "0032a1dc85f1c9786925a2e71d8272dd");
}

/* ============================================================== */
/* RFC 9001 §A.1: QUIC Initial AEAD application of AES-128-GCM    */
/* ============================================================== */

static void test_aes128_gcm_rfc9001(void) {
    printf("== AES-128-GCM: RFC 9001 §A.2 client Initial ==\n");
    /* RFC 9001 Appendix A.2: a client Initial packet.
     *   client_initial_secret =
     *     c00cf151ca5be075ed0ebfb5c80323c4
     *     2d6b7db67881289af4008f1f6c357aea
     *   key (Initial AEAD key) =
     *     1f369613dd76d5467730efcbe3b1a22d
     *   iv = fa044b2f42a3fd3b46fb255c
     *
     * We only test the AEAD primitive, not header-protection
     * (HP is exercised via AES-ECB above).
     *
     * Use a synthetic plaintext + tag we computed offline by
     * sealing one byte under these keys; smoke-tests that the
     * Initial keys work end-to-end with our AEAD. The actual
     * RFC 9001 packet vector is tested in the full QUIC
     * integration suite (later phase); here we just confirm
     * seal/open round-trips correctly under the Initial key.
     */
    uint8_t key[16], iv[12];
    unhex("1f369613dd76d5467730efcbe3b1a22d", key, 16);
    unhex("fa044b2f42a3fd3b46fb255c",         iv,  12);

    const uint8_t aad[] = { 0xc3, 0x00, 0x00, 0x00, 0x01 };  /* truncated long header */
    const uint8_t pt[]  = { 0x06, 0x00, 0x40, 0xee };         /* CRYPTO frame prefix */

    uint8_t ct[sizeof pt], tag[16];
    aes128_gcm_seal(key, iv, aad, sizeof aad, pt, sizeof pt, ct, tag);

    uint8_t recovered[sizeof pt];
    int rc = aes128_gcm_open(key, iv,
                             aad, sizeof aad,
                             ct, sizeof pt,
                             tag, recovered);
    check_int("Initial-key seal/open round-trip", rc, 0);
    check_eq("Initial-key plaintext recovered", recovered, pt, sizeof pt);
}

/* ============================================================== */
/* QUIC varint (RFC 9000 §16)                                     */
/* ============================================================== */

static void test_quic_varint(void) {
    printf("== QUIC varint (RFC 9000 §16) ==\n");
    /* RFC 9000 §A.1 sample encodings. */
    struct { uint64_t v; const char* hex; } cases[] = {
        { 0,                   "00" },
        { 63,                  "3f" },
        { 64,                  "4040" },
        { 16383,               "7fff" },
        { 16384,               "80004000" },
        { 1073741823,          "bfffffff" },
        { 1073741824,          "c000000040000000" },
        { UINT64_C(151288809941952652), "c2197c5eff14e88c" },  /* §A.1 example */
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t buf[8], expect[8];
        size_t want_n = unhex(cases[i].hex, expect, sizeof expect);
        size_t got_n  = quic_varint_encode(buf, sizeof buf, cases[i].v);
        check_int("encode length", (long)got_n, (long)want_n);
        check_eq("encode bytes", buf, expect, want_n);
        uint64_t dv = 0;
        size_t   dn = quic_varint_decode(buf, got_n, &dv);
        check_int("decode length", (long)dn, (long)got_n);
        check_int("decode value", (long)dv, (long)cases[i].v);
    }
}

/* ============================================================== */
/* RFC 9001 §A.1 — Initial key derivation                         */
/* ============================================================== */

static void test_quic_initial_keys_a1(void) {
    printf("== QUIC Initial keys (RFC 9001 §A.1) ==\n");
    uint8_t dcid[8];
    unhex("8394c8f03e515708", dcid, 8);

    quic_initial_keys_t client, server;
    quic_initial_derive(dcid, sizeof dcid, 0, &client);
    quic_initial_derive(dcid, sizeof dcid, 1, &server);

    uint8_t expect[16];
    unhex("1f369613dd76d5467730efcbe3b1a22d", expect, 16);
    check_eq("client key", client.key, expect, 16);

    unhex("fa044b2f42a3fd3b46fb255c", expect, 12);
    check_eq("client iv",  client.iv,  expect, 12);

    unhex("9f50449e04a0e810283a1e9933adedd2", expect, 16);
    check_eq("client hp",  client.hp,  expect, 16);

    unhex("cf3a5331653c364c88f0f379b6067e37", expect, 16);
    check_eq("server key", server.key, expect, 16);

    unhex("0ac1493ca1905853b0bba03e", expect, 12);
    check_eq("server iv",  server.iv,  expect, 12);

    unhex("c206b8d9b9f0f37644430b490eeaa314", expect, 16);
    check_eq("server hp",  server.hp,  expect, 16);
}

/* ============================================================== */
/* RFC 9001 §A.3 — Server Initial: build and match wire bytes     */
/* ============================================================== */

/* Hex form of the unprotected server Initial frames (A.3 §1). */
static const char SERVER_INITIAL_FRAMES_HEX[] =
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304";

/* Hex form of the final protected server Initial packet (A.3 §7). */
static const char SERVER_INITIAL_PROTECTED_HEX[] =
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
    "2158407dd074ee";

static void test_quic_initial_build_a3(void) {
    printf("== QUIC server Initial build (RFC 9001 §A.3) ==\n");
    uint8_t dcid[8];
    unhex("8394c8f03e515708", dcid, 8);
    quic_initial_keys_t server_keys;
    quic_initial_derive(dcid, sizeof dcid, 1, &server_keys);

    uint8_t frames[256];
    size_t frames_n = unhex(SERVER_INITIAL_FRAMES_HEX, frames, sizeof frames);
    check_int("server frame length", (long)frames_n, 99);

    quic_initial_pkt_t pkt = {0};
    pkt.version = 0x00000001u;
    pkt.dcid_len = 0;                  /* server's outbound DCID is empty */
    unhex("f067a5502a4262b5", pkt.scid, 8);
    pkt.scid_len = 8;
    pkt.token_len = 0;
    pkt.pn = 1;
    pkt.pn_len = 2;
    pkt.payload = frames;
    pkt.payload_len = frames_n;

    uint8_t out[2048];
    size_t n = quic_initial_build(out, sizeof out, &pkt, &server_keys, 0);

    uint8_t expect[2048];
    size_t expect_n = unhex(SERVER_INITIAL_PROTECTED_HEX, expect, sizeof expect);
    check_int("built length matches expected", (long)n, (long)expect_n);
    if (n == expect_n) {
        check_eq("server Initial wire bytes", out, expect, n);
    }
}

/* ============================================================== */
/* RFC 9001 §A.2 — Client Initial: parse, recover frames          */
/* ============================================================== */

static const char CLIENT_INITIAL_PROTECTED_HEX[] =
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
    "e221af44860018ab0856972e194cd934";

static const char CLIENT_INITIAL_FRAMES_HEX[] =
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c000004130113"
    "02010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a"
    "00080006001d00170018001000070005"
    "04616c706e0005000501000000000033"
    "00260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce1"
    "5d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408"
    "050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff050480"
    "00ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806"
    "048000ffff";

static void test_quic_initial_parse_a2(void) {
    printf("== QUIC client Initial parse (RFC 9001 §A.2) ==\n");
    uint8_t dcid_seed[8];
    unhex("8394c8f03e515708", dcid_seed, 8);
    quic_initial_keys_t client_keys;
    quic_initial_derive(dcid_seed, sizeof dcid_seed, 0, &client_keys);

    uint8_t wire[2048];
    size_t  wire_n = unhex(CLIENT_INITIAL_PROTECTED_HEX, wire, sizeof wire);
    check_int("client wire length", (long)wire_n, 1200);

    quic_initial_pkt_t pkt;
    uint8_t scratch[2048];
    int rc = quic_initial_parse(wire, wire_n, &client_keys, &pkt,
                                scratch, sizeof scratch);
    check_int("parse returns 0", rc, 0);

    if (rc == 0) {
        check_int("parsed pn", (long)pkt.pn, 2);
        check_int("parsed pn_len", (long)pkt.pn_len, 4);
        check_int("parsed dcid_len", (long)pkt.dcid_len, 8);
        check_int("parsed scid_len", (long)pkt.scid_len, 0);
        check_eq("parsed dcid", pkt.dcid, dcid_seed, 8);

        /* Recover frames hex and compare against §A.2 frame text.
         * The wire payload is 1162 bytes (frames + PADDING). */
        uint8_t expect_frames[1200];
        size_t expect_n = unhex(CLIENT_INITIAL_FRAMES_HEX, expect_frames,
                                sizeof expect_frames);
        check_int("frames text decodes ok", (long)expect_n, 245);
        check_int("decrypted payload length is 1162",
                  (long)pkt.payload_len, 1162);
        if (pkt.payload_len >= expect_n) {
            check_eq("decrypted prefix == frames text",
                     pkt.payload, expect_frames, expect_n);
            /* Remaining bytes must all be PADDING (0x00). */
            int all_zero = 1;
            for (size_t i = expect_n; i < pkt.payload_len; i++) {
                if (pkt.payload[i] != 0) { all_zero = 0; break; }
            }
            check_int("PADDING tail is all zero", all_zero, 1);
        }
    }
}

/* ============================================================== */
/* Phase 4a — QUIC frame codec (RFC 9000 §19)                     */
/* ============================================================== */

static void test_frame_padding_and_ping(void) {
    printf("== QUIC frames: PADDING + PING ==\n");
    uint8_t buf[16];
    /* PADDING: encode 5 zeros, decode collapses to one frame. */
    size_t n = quic_frame_padding_encode(buf, sizeof buf, 5);
    check_int("padding encoded len", (long)n, 5);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("padding consumed", (long)c, 5);
    check_int("padding type", f.type, QUIC_FT_PADDING);
    check_int("padding count", (long)f.u.padding_count, 5);

    /* PING: 1 byte 0x01. */
    n = quic_frame_ping_encode(buf, sizeof buf);
    check_int("ping encoded len", (long)n, 1);
    c = quic_frame_decode(buf, n, &f);
    check_int("ping consumed", (long)c, 1);
    check_int("ping type", f.type, QUIC_FT_PING);

    /* HANDSHAKE_DONE: 1 byte 0x1e. */
    n = quic_frame_handshake_done_encode(buf, sizeof buf);
    check_int("hs_done encoded len", (long)n, 1);
    c = quic_frame_decode(buf, n, &f);
    check_int("hs_done type", f.type, QUIC_FT_HANDSHAKE_DONE);
}

static void test_frame_crypto_roundtrip(void) {
    printf("== QUIC frames: CRYPTO round-trip ==\n");
    uint8_t buf[300];
    uint8_t payload[241];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i & 0xff);
    size_t n = quic_frame_crypto_encode(buf, sizeof buf, 0,
                                        payload, sizeof payload);
    /* 1 (type) + 1 (offset varint) + 2 (length 241 -> 0x40f1) + 241. */
    check_int("crypto encoded len", (long)n, 1 + 1 + 2 + 241);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("crypto consumed", (long)c, (long)n);
    check_int("crypto type", f.type, QUIC_FT_CRYPTO);
    check_int("crypto offset", (long)f.u.crypto.offset, 0);
    check_int("crypto length", (long)f.u.crypto.length, 241);
    check_eq("crypto data view", f.u.crypto.data, payload, sizeof payload);

    /* Larger offset that needs 2-byte varint. */
    n = quic_frame_crypto_encode(buf, sizeof buf, 12345,
                                 payload, 10);
    c = quic_frame_decode(buf, n, &f);
    check_int("crypto2 consumed", (long)c, (long)n);
    check_int("crypto2 offset", (long)f.u.crypto.offset, 12345);
    check_int("crypto2 length", (long)f.u.crypto.length, 10);
}

static void test_frame_ack_roundtrip(void) {
    printf("== QUIC frames: ACK round-trip ==\n");
    uint8_t buf[32];
    /* ACKs packets [10..15], so largest=15, first_range=5, no extra. */
    size_t n = quic_frame_ack_encode(buf, sizeof buf, 15, 1234, 5);
    check_int("ack encoded byte0", buf[0], 0x02);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("ack consumed", (long)c, (long)n);
    check_int("ack type", f.type, QUIC_FT_ACK);
    check_int("ack largest", (long)f.u.ack.largest, 15);
    check_int("ack delay raw", (long)f.u.ack.delay, 1234);
    check_int("ack range_count", (long)f.u.ack.range_count, 0);
    check_int("ack first_range", (long)f.u.ack.first_range, 5);
    check_int("ack ecn off", f.u.ack.has_ecn, 0);
}

static void test_frame_stream_roundtrip(void) {
    printf("== QUIC frames: STREAM round-trip ==\n");
    uint8_t buf[64];
    const uint8_t data[] = "hello, h3";
    size_t n = quic_frame_stream_encode(buf, sizeof buf,
                                        4 /* stream id */, 100 /* offset */,
                                        data, sizeof data - 1, 1 /* fin */);
    check_int("stream byte0 has off|len|fin",
              buf[0], 0x08 | 0x04 | 0x02 | 0x01);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("stream consumed", (long)c, (long)n);
    check_int("stream type", f.type, QUIC_FT_STREAM);
    check_int("stream id", (long)f.u.stream.stream_id, 4);
    check_int("stream offset", (long)f.u.stream.offset, 100);
    check_int("stream length", (long)f.u.stream.length, sizeof data - 1);
    check_int("stream fin", f.u.stream.fin, 1);
    check_eq("stream data view", f.u.stream.data, data, sizeof data - 1);
}

static void test_frame_close_roundtrip(void) {
    printf("== QUIC frames: CONNECTION_CLOSE round-trip ==\n");
    uint8_t buf[64];
    const uint8_t reason[] = "bye";
    /* Transport close: 0x1c, error 0x07 (FRAME_ENCODING_ERROR), frame_type 0. */
    size_t n = quic_frame_close_encode(buf, sizeof buf, 0, 0x07, 0,
                                       reason, sizeof reason - 1);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("close consumed", (long)c, (long)n);
    check_int("close type", f.type, QUIC_FT_CONNECTION_CLOSE);
    check_int("close is_app", f.u.close.is_app, 0);
    check_int("close error", (long)f.u.close.error_code, 0x07);
    check_int("close frame_type", (long)f.u.close.frame_type, 0);
    check_int("close reason_len", (long)f.u.close.reason_len, 3);
    check_eq("close reason", f.u.close.reason, reason, 3);

    /* App close: 0x1d (no frame_type field). */
    n = quic_frame_close_encode(buf, sizeof buf, 1, 0x100, 0, NULL, 0);
    c = quic_frame_decode(buf, n, &f);
    check_int("close_app consumed", (long)c, (long)n);
    check_int("close_app type", f.type, QUIC_FT_CONNECTION_CLOSE_A);
    check_int("close_app is_app", f.u.close.is_app, 1);
    check_int("close_app error", (long)f.u.close.error_code, 0x100);
    check_int("close_app reason_len", (long)f.u.close.reason_len, 0);
}

/* RFC 9001 §A.3 server frames: ACK followed by CRYPTO(ServerHello). */
static void test_frame_decode_a3_payload(void) {
    printf("== QUIC frames: decode RFC 9001 §A.3 server payload ==\n");
    uint8_t frames[256];
    size_t frames_n = unhex(SERVER_INITIAL_FRAMES_HEX, frames, sizeof frames);
    check_int("a3 frames length", (long)frames_n, 99);

    size_t off = 0;
    quic_frame_t f;
    /* Frame 1: ACK 0x02 largest=0 delay=0 range_count=0 first_range=0. */
    size_t c = quic_frame_decode(frames + off, frames_n - off, &f);
    check_int("a3 frame1 consumed", (long)c, 5);
    check_int("a3 frame1 type", f.type, QUIC_FT_ACK);
    check_int("a3 frame1 largest", (long)f.u.ack.largest, 0);
    check_int("a3 frame1 first_range", (long)f.u.ack.first_range, 0);
    off += c;

    /* Frame 2: CRYPTO 0x06 offset=0 length=0x405a (=90) data=ServerHello. */
    c = quic_frame_decode(frames + off, frames_n - off, &f);
    check_int("a3 frame2 type", f.type, QUIC_FT_CRYPTO);
    check_int("a3 frame2 offset", (long)f.u.crypto.offset, 0);
    check_int("a3 frame2 length", (long)f.u.crypto.length, 90);
    /* ServerHello starts with 0x02 (handshake type) 0x00 0x00 0x56 (length=86). */
    check_int("a3 frame2 sh type", f.u.crypto.data[0], 0x02);
    check_int("a3 frame2 sh len_lo", f.u.crypto.data[3], 0x56);
    off += c;
    check_int("a3 fully consumed", (long)off, (long)frames_n);
}

/* RFC 9001 §A.2 client decrypted payload: CRYPTO(ClientHello) + PADDING. */
static void test_frame_decode_a2_payload(void) {
    printf("== QUIC frames: decode RFC 9001 §A.2 client payload ==\n");
    /* Re-derive client keys, parse the wire packet, then iterate frames. */
    uint8_t dcid_seed[8];
    unhex("8394c8f03e515708", dcid_seed, 8);
    quic_initial_keys_t client_keys;
    quic_initial_derive(dcid_seed, sizeof dcid_seed, 0, &client_keys);

    uint8_t wire[1500];
    size_t wire_n = unhex(CLIENT_INITIAL_PROTECTED_HEX, wire, sizeof wire);
    quic_initial_pkt_t pkt;
    uint8_t scratch[2048];
    int rc = quic_initial_parse(wire, wire_n, &client_keys, &pkt,
                                scratch, sizeof scratch);
    check_int("a2 parse returns 0", rc, 0);
    if (rc != 0) return;

    /* Frame 1: CRYPTO offset=0 length=241 (varint 0x40 0xf1). */
    quic_frame_t f;
    size_t c = quic_frame_decode(pkt.payload, pkt.payload_len, &f);
    check_int("a2 frame1 type", f.type, QUIC_FT_CRYPTO);
    check_int("a2 frame1 offset", (long)f.u.crypto.offset, 0);
    check_int("a2 frame1 length", (long)f.u.crypto.length, 241);
    /* ClientHello handshake type. */
    check_int("a2 frame1 ch type", f.u.crypto.data[0], 0x01);

    /* Frame 2: PADDING run to end of payload. */
    size_t consumed = c;
    c = quic_frame_decode(pkt.payload + consumed,
                          pkt.payload_len - consumed, &f);
    check_int("a2 frame2 type", f.type, QUIC_FT_PADDING);
    check_int("a2 frame2 spans rest",
              (long)f.u.padding_count,
              (long)(pkt.payload_len - consumed));
    consumed += c;
    check_int("a2 fully consumed", (long)consumed, (long)pkt.payload_len);
}

static void test_frame_decode_errors(void) {
    printf("== QUIC frames: decode error paths ==\n");
    quic_frame_t f;
    /* Truncated CRYPTO: type + offset + length, but data missing. */
    uint8_t buf1[] = { 0x06, 0x00, 0x40, 0x05, 0x01, 0x02 };  /* len=5, only 2 */
    size_t c = quic_frame_decode(buf1, sizeof buf1, &f);
    check_int("crypto truncated rejected", c == QUIC_FRAME_DECODE_ERROR, 1);

    /* Truncated STREAM: OFF|LEN bits, length larger than remaining bytes. */
    uint8_t buf2[] = { 0x0e, 0x04, 0x00, 0x40, 0x10, 0xaa };
    c = quic_frame_decode(buf2, sizeof buf2, &f);
    check_int("stream truncated rejected", c == QUIC_FRAME_DECODE_ERROR, 1);

    /* NEW_TOKEN with length=0 is illegal per RFC 9000 §19.7. */
    uint8_t buf3[] = { 0x07, 0x00 };
    c = quic_frame_decode(buf3, sizeof buf3, &f);
    check_int("new_token zero-len rejected", c == QUIC_FRAME_DECODE_ERROR, 1);

    /* Empty input returns 0 (not an error). */
    c = quic_frame_decode(NULL, 0, &f);
    check_int("empty input returns 0", (long)c, 0);
}

/* ============================================================== */
/* Phase 4b — RFC 9002 loss detection                              */
/* ============================================================== */

static void test_rtt_first_sample(void) {
    printf("== RTT: first sample (RFC 9002 §5.3) ==\n");
    quic_rtt_t r; quic_rtt_init(&r);
    quic_rtt_sample(&r, 10000, 500, 0);  /* 10 ms sample, 0.5 ms ack_delay */
    check_int("first_sample flag set", r.first_sample, 1);
    check_int("smoothed_rtt = sample", (long)r.smoothed_rtt, 10000);
    check_int("rttvar = sample/2",     (long)r.rttvar,       5000);
    check_int("min_rtt = sample",      (long)r.min_rtt,      10000);
    check_int("latest_rtt = sample",   (long)r.latest_rtt,   10000);
}

static void test_rtt_subsequent_samples(void) {
    printf("== RTT: subsequent samples ==\n");
    quic_rtt_t r; quic_rtt_init(&r);
    quic_rtt_sample(&r, 10000, 0, 0);  /* srtt=10000 rttvar=5000 */
    /* Second sample 12000us, ack_delay 1000us. min_rtt=10000.
     * 12000 >= 10000+1000 ⇒ adjusted = 11000.
     * rttvar' = (3*5000 + |10000-11000|)/4 = (15000+1000)/4 = 4000.
     * srtt'   = (7*10000 + 11000)/8 = 81000/8 = 10125. */
    quic_rtt_sample(&r, 12000, 1000, 25000);
    check_int("rttvar after 2nd",  (long)r.rttvar,       4000);
    check_int("srtt after 2nd",    (long)r.smoothed_rtt, 10125);
    check_int("min_rtt unchanged", (long)r.min_rtt,      10000);

    /* Third sample 8000us — below min_rtt+ack_delay, so no ack_delay sub. */
    /* adjusted = 8000. rttvar' = (3*4000 + |10125-8000|)/4 = (12000+2125)/4 = 3531.
     * srtt'    = (7*10125 + 8000)/8 = 78875/8 = 9859. min_rtt=8000. */
    quic_rtt_sample(&r, 8000, 5000, 25000);
    check_int("min_rtt drops to 8000", (long)r.min_rtt, 8000);
    check_int("rttvar after 3rd",      (long)r.rttvar, 3531);
    check_int("srtt after 3rd",        (long)r.smoothed_rtt, 9859);
}

static void test_rtt_caps_ack_delay(void) {
    printf("== RTT: ack_delay capped by max_ack_delay ==\n");
    quic_rtt_t r; quic_rtt_init(&r);
    quic_rtt_sample(&r, 10000, 0, 0);
    /* Sample 20000us, peer reports ack_delay=15000, but max=2500.
     * Effective delay = 2500. adjusted = 17500.
     * rttvar' = (3*5000 + |10000-17500|)/4 = (15000+7500)/4 = 5625.
     * srtt'   = (7*10000 + 17500)/8 = 87500/8 = 10937. */
    quic_rtt_sample(&r, 20000, 15000, 2500);
    check_int("srtt with capped delay", (long)r.smoothed_rtt, 10937);
    check_int("rttvar with capped delay", (long)r.rttvar, 5625);
}

static void test_loss_on_sent_and_ack(void) {
    printf("== loss: send + ack basic ==\n");
    quic_loss_t l; quic_loss_init(&l);
    quic_rtt_t  r; quic_rtt_init(&r);

    quic_loss_on_sent(&l, /*pn*/0, /*now*/2900, /*size*/100, /*elicit*/1, /*inflight*/1);
    quic_loss_on_sent(&l, /*pn*/1, /*now*/2950, /*size*/100, /*elicit*/1, /*inflight*/1);
    check_int("eliciting in flight", (long)l.ack_eliciting_in_flight, 2);

    quic_pn_range_t r1[] = { {1, 1} };
    size_t lost_count = 0;
    size_t newly = quic_loss_on_ack(&l, &r, r1, 1,
                                    /*ack_delay*/0, /*max_ack_delay*/25000,
                                    /*now*/3000, NULL, 0, &lost_count);
    check_int("newly_acked", (long)newly, 1);
    check_int("eliciting now 1", (long)l.ack_eliciting_in_flight, 1);
    check_int("largest_acked tracked", (long)l.largest_acked, 1);
    check_int("first RTT sample taken", r.first_sample, 1);
    check_int("RTT sample == 50us", (long)r.smoothed_rtt, 50);
    check_int("no losses yet", (long)lost_count, 0);
}

static void test_loss_packet_threshold(void) {
    printf("== loss: packet threshold ==\n");
    quic_loss_t l; quic_loss_init(&l);
    quic_rtt_t  r; quic_rtt_init(&r);

    /* Send pn 0..4, all eliciting. */
    for (uint64_t pn = 0; pn < 5; pn++) {
        quic_loss_on_sent(&l, pn, 1000 + pn, 100, 1, 1);
    }
    /* ACK pn 4 only. Threshold = 3 ⇒ pn 0, 1 are lost (4-pn >= 3). */
    quic_pn_range_t rg[] = { {4, 4} };
    uint64_t lost[8];
    size_t lost_count = 0;
    quic_loss_on_ack(&l, &r, rg, 1, 0, 25000, 5000, lost, 8, &lost_count);
    check_int("packet-threshold lost count", (long)lost_count, 2);
    /* PNs 0 and 1 should be reported (order independent — sort). */
    if (lost_count == 2) {
        uint64_t lo = lost[0] < lost[1] ? lost[0] : lost[1];
        uint64_t hi = lost[0] < lost[1] ? lost[1] : lost[0];
        check_int("lost lo == 0", (long)lo, 0);
        check_int("lost hi == 1", (long)hi, 1);
    }
}

static void test_loss_time_threshold(void) {
    printf("== loss: time threshold ==\n");
    quic_loss_t l; quic_loss_init(&l);
    quic_rtt_t  r; quic_rtt_init(&r);

    /* Prime RTT to 10000us so loss_delay = 9/8*10000 = 11250us. */
    quic_rtt_sample(&r, 10000, 0, 0);

    /* Send pn 0 at t=0, pn 1 at t=100000. */
    quic_loss_on_sent(&l, 0, 0,      100, 1, 1);
    quic_loss_on_sent(&l, 1, 100000, 100, 1, 1);

    /* ACK pn 1 at t=110000. pn 0 is within packet threshold (gap=1<3),
     * but its send time (0) <= now-loss_delay (110000-11250=98750), so
     * it should be marked lost by time threshold. */
    quic_pn_range_t rg[] = { {1, 1} };
    uint64_t lost[4]; size_t lost_count = 0;
    quic_loss_on_ack(&l, &r, rg, 1, 0, 25000, 110000, lost, 4, &lost_count);
    check_int("time-threshold lost count", (long)lost_count, 1);
    if (lost_count == 1) check_int("lost pn", (long)lost[0], 0);
}

static void test_loss_no_rtt_for_non_eliciting(void) {
    printf("== loss: ACK of non-eliciting does not sample RTT ==\n");
    quic_loss_t l; quic_loss_init(&l);
    quic_rtt_t  r; quic_rtt_init(&r);
    /* pn 0 is non-eliciting (e.g. pure-ACK packet). */
    quic_loss_on_sent(&l, 0, 1000, 50, /*elicit*/0, /*inflight*/0);
    quic_pn_range_t rg[] = { {0, 0} };
    quic_loss_on_ack(&l, &r, rg, 1, 0, 25000, 3000, NULL, 0, NULL);
    check_int("no RTT sample taken", r.first_sample, 0);
    check_int("eliciting count still 0", (long)l.ack_eliciting_in_flight, 0);
}

static void test_loss_pto(void) {
    printf("== loss: PTO formula ==\n");
    quic_rtt_t r; quic_rtt_init(&r);
    /* No sample → 0. */
    check_int("PTO==0 before sample", (long)quic_loss_pto_us(&r, 0), 0);

    quic_rtt_sample(&r, 10000, 0, 0);  /* srtt=10000 rttvar=5000 */
    /* PTO = srtt + max(4*rttvar, 1000) + max_ack_delay
     *     = 10000 + max(20000, 1000) + 25000
     *     = 55000us */
    check_int("PTO formula",
              (long)quic_loss_pto_us(&r, 25000), 55000);

    /* Deadline back-off: with no eliciting in flight ⇒ 0. */
    quic_loss_t l; quic_loss_init(&l);
    check_int("deadline 0 with nothing in flight",
              (long)quic_loss_pto_deadline(&l, &r, 25000), 0);

    /* After sending an eliciting packet at t=10000, deadline = 10000+55000. */
    quic_loss_on_sent(&l, 0, 10000, 100, 1, 1);
    check_int("deadline base", (long)quic_loss_pto_deadline(&l, &r, 25000),
              10000 + 55000);

    /* pto_count=2 ⇒ shift base by 4. */
    l.pto_count = 2;
    check_int("deadline backed off",
              (long)quic_loss_pto_deadline(&l, &r, 25000),
              10000 + 4 * 55000);
}

static void test_loss_pto_resets_on_ack(void) {
    printf("== loss: ACK resets pto_count ==\n");
    quic_loss_t l; quic_loss_init(&l);
    quic_rtt_t  r; quic_rtt_init(&r);
    quic_loss_on_sent(&l, 0, 1000, 100, 1, 1);
    l.pto_count = 3;
    quic_pn_range_t rg[] = { {0, 0} };
    quic_loss_on_ack(&l, &r, rg, 1, 0, 25000, 2000, NULL, 0, NULL);
    check_int("pto_count reset", (long)l.pto_count, 0);
}

/* ============================================================== */
/* Phase 4c — NewReno congestion control + flow control            */
/* ============================================================== */

static void test_cc_initial_window(void) {
    printf("== CC: initial window (RFC 9002 §B) ==\n");
    /* MDS=1200 ⇒ min(12000, max(2400, 14720)) = min(12000, 14720) = 12000. */
    check_int("iw(1200) = 12000", (long)quic_cc_initial_window(1200), 12000);
    /* MDS=1500 ⇒ min(15000, max(3000, 14720)) = min(15000, 14720) = 14720. */
    check_int("iw(1500) = 14720", (long)quic_cc_initial_window(1500), 14720);
    /* MDS=8000 ⇒ min(80000, max(16000, 14720)) = min(80000, 16000) = 16000. */
    check_int("iw(8000) = 16000", (long)quic_cc_initial_window(8000), 16000);
    check_int("min(1200) = 2400", (long)quic_cc_minimum_window(1200), 2400);
}

static void test_cc_init(void) {
    printf("== CC: init state ==\n");
    quic_cc_t cc;
    quic_cc_init(&cc, 1200);
    check_int("cwnd = iw", (long)cc.cwnd, 12000);
    check_int("bytes_in_flight = 0", (long)cc.bytes_in_flight, 0);
    check_int("ssthresh = max", cc.ssthresh == UINT64_MAX, 1);
    check_int("not in recovery", (long)cc.congestion_recovery_start_time, 0);
    check_int("can send full window", quic_cc_can_send(&cc, 12000), 1);
    check_int("cannot send beyond window", quic_cc_can_send(&cc, 12001), 0);
}

static void test_cc_slow_start(void) {
    printf("== CC: slow start growth ==\n");
    quic_cc_t cc;
    quic_cc_init(&cc, 1200);
    quic_cc_on_sent(&cc, 1200);
    quic_cc_on_sent(&cc, 1200);
    check_int("bytes_in_flight 2400", (long)cc.bytes_in_flight, 2400);
    quic_cc_on_acked(&cc, 1200);
    check_int("bif drops to 1200", (long)cc.bytes_in_flight, 1200);
    /* Slow start: cwnd grows by acked bytes (12000 + 1200 = 13200). */
    check_int("cwnd grew by acked",  (long)cc.cwnd, 13200);
}

static void test_cc_loss_then_ca(void) {
    printf("== CC: loss enters CA, RTT-once recovery period ==\n");
    quic_cc_t cc;
    quic_cc_init(&cc, 1200);
    /* Pretend we sent and have 4800 in flight. */
    quic_cc_on_sent(&cc, 4800);
    /* Loss of 1200 bytes at t=10000, send_time=5000. */
    quic_cc_on_lost(&cc, 1200, /*lost_send_time*/5000, /*now*/10000);
    check_int("ssthresh = cwnd/2 = 6000", (long)cc.ssthresh, 6000);
    check_int("cwnd = ssthresh = 6000",   (long)cc.cwnd, 6000);
    check_int("bif decremented",          (long)cc.bytes_in_flight, 3600);
    check_int("recovery start = now",     (long)cc.congestion_recovery_start_time, 10000);

    /* Second loss inside recovery period: must NOT halve again. */
    quic_cc_on_lost(&cc, 1200, /*lost_send_time*/8000, /*now*/11000);
    check_int("cwnd unchanged in recovery", (long)cc.cwnd, 6000);
    check_int("bif decremented again",      (long)cc.bytes_in_flight, 2400);

    /* Now in CA (cwnd >= ssthresh). On ACK of 1200B:
     * cwnd += MDS * acked / cwnd = 1200 * 1200 / 6000 = 240. */
    quic_cc_on_acked(&cc, 1200);
    check_int("CA growth", (long)cc.cwnd, 6240);

    /* Loss from a packet sent AFTER recovery start ⇒ react again. */
    quic_cc_on_lost(&cc, 1200, /*lost_send_time*/15000, /*now*/16000);
    check_int("ssthresh halved again", (long)cc.ssthresh, 3120);
    check_int("cwnd to new ssthresh",  (long)cc.cwnd, 3120);
}

static void test_cc_loss_floor_at_min_window(void) {
    printf("== CC: loss floors cwnd at kMinimumWindow ==\n");
    quic_cc_t cc;
    quic_cc_init(&cc, 1200);
    /* Force a tiny cwnd by hand and trigger loss. */
    cc.cwnd = 3000;
    quic_cc_on_lost(&cc, 0, /*lost_send_time*/100, /*now*/200);
    /* halved=1500 < min=2400 ⇒ ssthresh=2400. */
    check_int("ssthresh floored", (long)cc.ssthresh, 2400);
    check_int("cwnd floored",     (long)cc.cwnd, 2400);
}

static void test_cc_persistent_congestion(void) {
    printf("== CC: persistent congestion collapses cwnd ==\n");
    quic_cc_t cc;
    quic_cc_init(&cc, 1200);
    cc.cwnd = 50000;
    cc.congestion_recovery_start_time = 12345;
    quic_cc_on_persistent_congestion(&cc);
    check_int("cwnd = kMinimumWindow", (long)cc.cwnd, 2400);
    check_int("recovery cleared",      (long)cc.congestion_recovery_start_time, 0);
}

static void test_flow_basic(void) {
    printf("== flow: consume + available + max-only-grows ==\n");
    quic_flow_t f;
    quic_flow_init(&f, 1000);
    check_int("initial avail", (long)quic_flow_available(&f), 1000);
    check_int("consume 400 = 400", (long)quic_flow_consume(&f, 400), 400);
    check_int("avail 600", (long)quic_flow_available(&f), 600);
    /* Request 1000, only 600 granted. */
    check_int("consume 1000 = 600", (long)quic_flow_consume(&f, 1000), 600);
    check_int("avail 0", (long)quic_flow_available(&f), 0);
    check_int("consume 1 = 0", (long)quic_flow_consume(&f, 1), 0);
    /* Bump max up. */
    quic_flow_set_max(&f, 1500);
    check_int("avail 500 after grow", (long)quic_flow_available(&f), 500);
    /* Smaller max ignored. */
    quic_flow_set_max(&f, 100);
    check_int("smaller max ignored", (long)f.max, 1500);
}

static void test_flow_should_update(void) {
    printf("== flow: should_update threshold ==\n");
    quic_flow_t f;
    quic_flow_init(&f, 1000);
    check_int("no update at start",    quic_flow_should_update(&f, 1000), 0);
    quic_flow_consume(&f, 499);
    check_int("no update <half",       quic_flow_should_update(&f, 1000), 0);
    quic_flow_consume(&f, 1);
    check_int("update at half",        quic_flow_should_update(&f, 1000), 1);
    quic_flow_consume(&f, 500);
    check_int("update when exhausted", quic_flow_should_update(&f, 1000), 1);
}

/* ============================================================== */
/* Phase 4d — auxiliary frames + special packets + idle           */
/* ============================================================== */

static void test_aux_reset_stream_roundtrip(void) {
    printf("== aux: RESET_STREAM round-trip ==\n");
    uint8_t buf[16];
    size_t n = quic_frame_reset_stream_encode(buf, sizeof buf,
                                              4, 0x100, 1024);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("rs consumed", (long)c, (long)n);
    check_int("rs type",  f.type, QUIC_FT_RESET_STREAM);
    check_int("rs sid",   (long)f.u.reset_stream.stream_id,      4);
    check_int("rs err",   (long)f.u.reset_stream.app_error_code, 0x100);
    check_int("rs final", (long)f.u.reset_stream.final_size,     1024);
}

static void test_aux_stop_sending_roundtrip(void) {
    printf("== aux: STOP_SENDING round-trip ==\n");
    uint8_t buf[16];
    size_t n = quic_frame_stop_sending_encode(buf, sizeof buf, 8, 0x42);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("ss consumed", (long)c, (long)n);
    check_int("ss type", f.type, QUIC_FT_STOP_SENDING);
    check_int("ss sid",  (long)f.u.stop_sending.stream_id,      8);
    check_int("ss err",  (long)f.u.stop_sending.app_error_code, 0x42);
}

static void test_aux_max_frames_roundtrip(void) {
    printf("== aux: MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS round-trip ==\n");
    uint8_t buf[16];
    quic_frame_t f;
    size_t n = quic_frame_max_data_encode(buf, sizeof buf, 1048576);
    quic_frame_decode(buf, n, &f);
    check_int("max_data type", f.type, QUIC_FT_MAX_DATA);
    check_int("max_data val",  (long)f.u.max_data.max, 1048576);

    n = quic_frame_max_stream_data_encode(buf, sizeof buf, 4, 65536);
    quic_frame_decode(buf, n, &f);
    check_int("max_stream_data type", f.type, QUIC_FT_MAX_STREAM_DATA);
    check_int("max_stream_data sid",  (long)f.u.max_stream_data.stream_id, 4);
    check_int("max_stream_data max",  (long)f.u.max_stream_data.max,       65536);

    n = quic_frame_max_streams_encode(buf, sizeof buf, 0, 100);
    quic_frame_decode(buf, n, &f);
    check_int("max_streams_bidi type", f.type, QUIC_FT_MAX_STREAMS_BIDI);
    check_int("max_streams_bidi val",  (long)f.u.max_streams.max, 100);

    n = quic_frame_max_streams_encode(buf, sizeof buf, 1, 50);
    quic_frame_decode(buf, n, &f);
    check_int("max_streams_uni type", f.type, QUIC_FT_MAX_STREAMS_UNI);
    check_int("max_streams_uni val",  (long)f.u.max_streams.max, 50);
}

static void test_aux_blocked_frames_roundtrip(void) {
    printf("== aux: DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED ==\n");
    uint8_t buf[16];
    quic_frame_t f;
    size_t n = quic_frame_data_blocked_encode(buf, sizeof buf, 1024);
    quic_frame_decode(buf, n, &f);
    check_int("data_blocked type", f.type, QUIC_FT_DATA_BLOCKED);
    check_int("data_blocked limit", (long)f.u.data_blocked.limit, 1024);

    n = quic_frame_stream_data_blocked_encode(buf, sizeof buf, 4, 512);
    quic_frame_decode(buf, n, &f);
    check_int("sdb type", f.type, QUIC_FT_STREAM_DATA_BLOCK);
    check_int("sdb sid",  (long)f.u.stream_data_blocked.stream_id, 4);
    check_int("sdb lim",  (long)f.u.stream_data_blocked.limit,     512);

    n = quic_frame_streams_blocked_encode(buf, sizeof buf, 0, 10);
    quic_frame_decode(buf, n, &f);
    check_int("sb_bidi type", f.type, QUIC_FT_STREAMS_BLOCK_BIDI);
    check_int("sb_bidi limit", (long)f.u.streams_blocked.limit, 10);

    n = quic_frame_streams_blocked_encode(buf, sizeof buf, 1, 5);
    quic_frame_decode(buf, n, &f);
    check_int("sb_uni type", f.type, QUIC_FT_STREAMS_BLOCK_UNI);
    check_int("sb_uni limit", (long)f.u.streams_blocked.limit, 5);
}

static void test_aux_new_conn_id_roundtrip(void) {
    printf("== aux: NEW_CONNECTION_ID round-trip ==\n");
    uint8_t buf[64];
    uint8_t cid[8]   = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    uint8_t token[16];
    for (int i = 0; i < 16; i++) token[i] = (uint8_t)(i * 17);
    size_t n = quic_frame_new_conn_id_encode(buf, sizeof buf,
                                             3, 1, cid, sizeof cid, token);
    /* 1 (type) + 1 (seq) + 1 (rpt) + 1 (cid_len) + 8 (cid) + 16 (token). */
    check_int("nci encoded len", (long)n, 1 + 1 + 1 + 1 + 8 + 16);
    quic_frame_t f;
    size_t c = quic_frame_decode(buf, n, &f);
    check_int("nci consumed", (long)c, (long)n);
    check_int("nci type", f.type, QUIC_FT_NEW_CONNECTION_ID);
    check_int("nci seq",  (long)f.u.new_conn_id.seq_no,          3);
    check_int("nci rpt",  (long)f.u.new_conn_id.retire_prior_to, 1);
    check_int("nci cid_len", f.u.new_conn_id.cid_len, 8);
    check_eq("nci cid",   f.u.new_conn_id.cid, cid, 8);
    check_eq("nci token", f.u.new_conn_id.stateless_reset_token, token, 16);

    /* Negative: cid_len=0 must be rejected. */
    uint8_t bad[] = { 0x18, 0x00, 0x00, 0x00,  /* type+seq+rpt+cid_len=0 */
                      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    c = quic_frame_decode(bad, sizeof bad, &f);
    check_int("nci cid_len=0 rejected", c == QUIC_FRAME_DECODE_ERROR, 1);
    /* Negative: cid_len=21 must be rejected. */
    uint8_t bad2[40] = { 0x18, 0x00, 0x00, 21 };
    c = quic_frame_decode(bad2, sizeof bad2, &f);
    check_int("nci cid_len=21 rejected", c == QUIC_FRAME_DECODE_ERROR, 1);
    /* Negative: retire_prior_to > seq must be rejected. */
    uint8_t bad3[] = { 0x18, 0x01, 0x05, 1, 0xaa,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    c = quic_frame_decode(bad3, sizeof bad3, &f);
    check_int("nci rpt>seq rejected", c == QUIC_FRAME_DECODE_ERROR, 1);
}

static void test_aux_retire_conn_id_and_path(void) {
    printf("== aux: RETIRE_CONNECTION_ID / PATH_CHALLENGE / PATH_RESPONSE ==\n");
    uint8_t buf[16];
    quic_frame_t f;

    size_t n = quic_frame_retire_conn_id_encode(buf, sizeof buf, 7);
    quic_frame_decode(buf, n, &f);
    check_int("rci type", f.type, QUIC_FT_RETIRE_CONN_ID);
    check_int("rci seq",  (long)f.u.retire_conn_id.seq_no, 7);

    uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    n = quic_frame_path_challenge_encode(buf, sizeof buf, data);
    check_int("path_chall encoded len", (long)n, 9);
    quic_frame_decode(buf, n, &f);
    check_int("path_chall type", f.type, QUIC_FT_PATH_CHALLENGE);
    check_eq("path_chall data", f.u.path.data, data, 8);

    n = quic_frame_path_response_encode(buf, sizeof buf, data);
    quic_frame_decode(buf, n, &f);
    check_int("path_resp type", f.type, QUIC_FT_PATH_RESPONSE);
    check_eq("path_resp data", f.u.path.data, data, 8);
}

static void test_special_stateless_reset_build_match(void) {
    printf("== special: stateless reset build + detect ==\n");
    uint8_t token[16];
    for (int i = 0; i < 16; i++) token[i] = (uint8_t)(0xa0 + i);
    uint8_t rand_buf[64];
    for (size_t i = 0; i < sizeof rand_buf; i++) rand_buf[i] = (uint8_t)(i ^ 0x55);

    uint8_t out[40];
    size_t n = quic_stateless_reset_build(out, sizeof out,
                                          rand_buf, sizeof rand_buf, token);
    check_int("sr length", (long)n, 40);
    check_int("sr fixed bit set",  (out[0] & 0x40) != 0, 1);
    check_int("sr form bit clear", (out[0] & 0x80) == 0, 1);
    check_eq("sr token tail", out + n - 16, token, 16);

    check_int("sr detect own packet", quic_stateless_reset_match(out, n, token), 1);
    /* Mutate one tail byte → no match. */
    out[n - 5] ^= 0x01;
    check_int("sr mutated rejected", quic_stateless_reset_match(out, n, token), 0);
    /* Too-short packet → no match. */
    check_int("sr short rejected",
              quic_stateless_reset_match(out, 15, token), 0);

    /* Capacity below minimum rejected. */
    check_int("sr below min rejected",
              (long)quic_stateless_reset_build(out, 21, rand_buf, sizeof rand_buf, token), 0);
    /* Insufficient randomness rejected. */
    check_int("sr insufficient rand rejected",
              (long)quic_stateless_reset_build(out, 30, rand_buf, 5, token), 0);
}

static void test_special_version_negotiation(void) {
    printf("== special: version negotiation packet ==\n");
    uint8_t cdcid[8] = { 1,2,3,4,5,6,7,8 };
    uint8_t cscid[4] = { 0xaa,0xbb,0xcc,0xdd };
    uint32_t versions[3] = { 0x00000001u, 0x709a50c4u /* Greasing */, 0xff00001du };
    uint8_t out[64];
    size_t n = quic_version_negotiation_build(out, sizeof out,
                                              0x55,
                                              cdcid, sizeof cdcid,
                                              cscid, sizeof cscid,
                                              versions, 3);
    /* 1 + 4 + 1 + 4 (echoed scid as dcid) + 1 + 8 (echoed dcid as scid)
     * + 3*4 versions = 31. */
    check_int("vn length", (long)n, 31);
    check_int("vn form bit set", (out[0] & 0x80) != 0, 1);
    /* Version field = 0. */
    check_int("vn ver byte 1", out[1], 0);
    check_int("vn ver byte 2", out[2], 0);
    check_int("vn ver byte 3", out[3], 0);
    check_int("vn ver byte 4", out[4], 0);
    /* dcid_len echoes client SCID (4). */
    check_int("vn dcid_len", out[5], 4);
    check_eq("vn dcid bytes", out + 6, cscid, 4);
    /* scid_len echoes client DCID (8). */
    check_int("vn scid_len", out[10], 8);
    check_eq("vn scid bytes", out + 11, cdcid, 8);
    /* Versions 1..3 at offsets 19, 23, 27 big-endian. */
    check_int("vn v0[0]", out[19], 0x00);
    check_int("vn v0[3]", out[22], 0x01);
    check_int("vn v2[0]", out[27], 0xff);
    check_int("vn v2[3]", out[30], 0x1d);
}

static void test_special_idle_expired(void) {
    printf("== special: idle timeout helper ==\n");
    /* 30s timeout, last recv at t=1_000_000us, now t=20_000_000us → not expired. */
    check_int("not yet expired",
              quic_idle_expired(1000000, 30000000, 20000000), 0);
    check_int("just expired",
              quic_idle_expired(1000000, 30000000, 31000000), 1);
    check_int("disabled timeout",
              quic_idle_expired(1000000, 0, 999999999), 0);
    check_int("clock backwards safe",
              quic_idle_expired(1000000, 30000000, 500000), 0);
}

/* ============================================================== */
/* Transport parameters (RFC 9000 §18)                            */
/* ============================================================== */

static void test_tp_defaults(void) {
    printf("== transport params: defaults ==\n");
    quic_transport_params_t tp;
    quic_tp_init_defaults(&tp);
    check_int("present mask cleared",          (long)tp.present, 0);
    check_int("max_udp_payload_size default",  (long)tp.max_udp_payload_size, 65527);
    check_int("ack_delay_exponent default",    (long)tp.ack_delay_exponent, 3);
    check_int("max_ack_delay_ms default",      (long)tp.max_ack_delay_ms, 25);
    check_int("active_cid_limit default",      (long)tp.active_connection_id_limit, 2);
}

static void test_tp_encode_empty(void) {
    printf("== transport params: encode empty ==\n");
    quic_transport_params_t tp;
    quic_tp_init_defaults(&tp);
    uint8_t buf[64];
    size_t n = quic_tp_encode(&tp, buf, sizeof buf);
    check_int("empty encodes to 0 bytes", (long)n, 0);
}

static void test_tp_encode_decode_roundtrip(void) {
    printf("== transport params: encode/decode round-trip ==\n");
    quic_transport_params_t in;
    quic_tp_init_defaults(&in);

    /* server-side typical set */
    static const uint8_t odcid[8]  = {1,2,3,4,5,6,7,8};
    static const uint8_t iscid[8]  = {9,10,11,12,13,14,15,16};
    static const uint8_t srt[16]   = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                      0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    memcpy(in.original_dcid, odcid, sizeof odcid);
    in.original_dcid_len = sizeof odcid;
    memcpy(in.initial_source_cid, iscid, sizeof iscid);
    in.initial_source_cid_len = sizeof iscid;
    memcpy(in.stateless_reset_token, srt, sizeof srt);

    in.max_idle_timeout_ms                       = 30000;
    in.max_udp_payload_size                      = 1452;
    in.initial_max_data                          = 1048576;
    in.initial_max_stream_data_bidi_local        = 65536;
    in.initial_max_stream_data_bidi_remote       = 65536;
    in.initial_max_stream_data_uni               = 65536;
    in.initial_max_streams_bidi                  = 100;
    in.initial_max_streams_uni                   = 3;
    in.ack_delay_exponent                        = 3;
    in.max_ack_delay_ms                          = 25;
    in.active_connection_id_limit                = 4;

    in.present = QUIC_TP_F_ORIGINAL_DCID
               | QUIC_TP_F_INITIAL_SOURCE_CID
               | QUIC_TP_F_STATELESS_RESET_TOKEN
               | QUIC_TP_F_MAX_IDLE_TIMEOUT
               | QUIC_TP_F_MAX_UDP_PAYLOAD_SIZE
               | QUIC_TP_F_INITIAL_MAX_DATA
               | QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
               | QUIC_TP_F_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
               | QUIC_TP_F_INITIAL_MAX_STREAM_DATA_UNI
               | QUIC_TP_F_INITIAL_MAX_STREAMS_BIDI
               | QUIC_TP_F_INITIAL_MAX_STREAMS_UNI
               | QUIC_TP_F_ACK_DELAY_EXPONENT
               | QUIC_TP_F_MAX_ACK_DELAY
               | QUIC_TP_F_DISABLE_ACTIVE_MIGRATION
               | QUIC_TP_F_ACTIVE_CONNECTION_ID_LIMIT;

    uint8_t buf[256];
    size_t n = quic_tp_encode(&in, buf, sizeof buf);
    if (!n) { printf("  FAIL: encode returned 0\n"); g_fail++; return; }
    printf("  PASS: encode produced %zu bytes\n", n); g_pass++;

    quic_transport_params_t out;
    int rc = quic_tp_decode(buf, n, &out);
    check_int("decode succeeds", rc, 1);
    check_int("present mask preserved",
              (long)out.present, (long)in.present);
    check_int("max_idle_timeout_ms",
              (long)out.max_idle_timeout_ms, 30000);
    check_int("max_udp_payload_size",
              (long)out.max_udp_payload_size, 1452);
    check_int("initial_max_data",
              (long)out.initial_max_data, 1048576);
    check_int("initial_max_streams_bidi",
              (long)out.initial_max_streams_bidi, 100);
    check_int("active_cid_limit",
              (long)out.active_connection_id_limit, 4);
    check_int("original_dcid_len", out.original_dcid_len, sizeof odcid);
    check_eq("original_dcid", out.original_dcid, odcid, sizeof odcid);
    check_int("initial_source_cid_len",
              out.initial_source_cid_len, sizeof iscid);
    check_eq("initial_source_cid", out.initial_source_cid, iscid, sizeof iscid);
    check_eq("stateless_reset_token",
             out.stateless_reset_token, srt, sizeof srt);
}

static void test_tp_decode_unknown_id_skipped(void) {
    printf("== transport params: unknown id is skipped ==\n");
    /* Build: known max_idle_timeout=30000, then unknown id 0x4242 (2-byte
     * varint = 0x42, 0x42 → wait, 0x4242 needs varint encoding).
     * Use a 1-byte unknown id 0x3f (63) which is reserved/unused. */
    uint8_t buf[32];
    size_t off = 0;
    /* id 0x01 (max_idle_timeout), len 4, value 30000 (varint 4-byte: 0x80 0x00 0x75 0x30) */
    buf[off++] = 0x01;
    buf[off++] = 0x04;
    buf[off++] = 0x80; buf[off++] = 0x00; buf[off++] = 0x75; buf[off++] = 0x30;
    /* unknown id 0x3f, len 3, value bytes */
    buf[off++] = 0x3f;
    buf[off++] = 0x03;
    buf[off++] = 0xaa; buf[off++] = 0xbb; buf[off++] = 0xcc;
    /* id 0x04 (initial_max_data), len 1, value 10 */
    buf[off++] = 0x04;
    buf[off++] = 0x01;
    buf[off++] = 0x0a;

    quic_transport_params_t tp;
    int rc = quic_tp_decode(buf, off, &tp);
    check_int("decode succeeds", rc, 1);
    check_int("max_idle_timeout_ms parsed",
              (long)tp.max_idle_timeout_ms, 30000);
    check_int("initial_max_data parsed",
              (long)tp.initial_max_data, 10);
    check_int("only known flags set",
              (long)(tp.present & ~(uint32_t)(QUIC_TP_F_MAX_IDLE_TIMEOUT
                                              | QUIC_TP_F_INITIAL_MAX_DATA)),
              0);
}

static void test_tp_decode_duplicate_rejected(void) {
    printf("== transport params: duplicate id rejected ==\n");
    /* Two max_idle_timeout entries → must fail. */
    uint8_t buf[] = {
        0x01, 0x01, 0x05,
        0x01, 0x01, 0x06,
    };
    quic_transport_params_t tp;
    int rc = quic_tp_decode(buf, sizeof buf, &tp);
    check_int("decode rejects duplicate", rc, 0);
}

static void test_tp_decode_truncated_rejected(void) {
    printf("== transport params: truncated TLV rejected ==\n");
    /* id=1, len=4, but only 2 bytes follow. */
    uint8_t buf[] = { 0x01, 0x04, 0x00, 0x01 };
    quic_transport_params_t tp;
    int rc = quic_tp_decode(buf, sizeof buf, &tp);
    check_int("decode rejects truncated value", rc, 0);
}

static void test_tp_decode_illegal_values(void) {
    printf("== transport params: illegal values rejected ==\n");
    quic_transport_params_t tp;
    int rc;

    /* max_udp_payload_size < 1200 (use 1199 → varint 2-byte 0x44 0xaf) */
    uint8_t b1[] = { 0x03, 0x02, 0x44, 0xaf };
    rc = quic_tp_decode(b1, sizeof b1, &tp);
    check_int("rejects max_udp_payload_size < 1200", rc, 0);

    /* ack_delay_exponent > 20 (set 21) */
    uint8_t b2[] = { 0x0a, 0x01, 0x15 };
    rc = quic_tp_decode(b2, sizeof b2, &tp);
    check_int("rejects ack_delay_exponent > 20", rc, 0);

    /* max_ack_delay >= 2^14 (16384, varint 4-byte: 0x80 0x00 0x40 0x00) */
    uint8_t b3[] = { 0x0b, 0x04, 0x80, 0x00, 0x40, 0x00 };
    rc = quic_tp_decode(b3, sizeof b3, &tp);
    check_int("rejects max_ack_delay >= 2^14", rc, 0);

    /* active_connection_id_limit < 2 (set 1) */
    uint8_t b4[] = { 0x0e, 0x01, 0x01 };
    rc = quic_tp_decode(b4, sizeof b4, &tp);
    check_int("rejects active_cid_limit < 2", rc, 0);

    /* stateless_reset_token wrong length (15) */
    uint8_t b5[18] = { 0x02, 0x0f };  /* 0x0f = 15 */
    rc = quic_tp_decode(b5, sizeof b5, &tp);
    check_int("rejects stateless_reset_token != 16B", rc, 0);

    /* original_dcid > 20 bytes (id=0, len=21) */
    uint8_t b6[24] = { 0x00, 0x15 };
    rc = quic_tp_decode(b6, sizeof b6, &tp);
    check_int("rejects original_dcid > 20B", rc, 0);

    /* disable_active_migration with non-zero length */
    uint8_t b7[] = { 0x0c, 0x01, 0x00 };
    rc = quic_tp_decode(b7, sizeof b7, &tp);
    check_int("rejects disable_active_migration with body", rc, 0);
}

static void test_tp_encode_validation(void) {
    printf("== transport params: encode validation ==\n");
    quic_transport_params_t tp;
    uint8_t buf[64];

    quic_tp_init_defaults(&tp);
    tp.present = QUIC_TP_F_MAX_UDP_PAYLOAD_SIZE;
    tp.max_udp_payload_size = 1199;
    check_int("encode rejects payload < 1200",
              (long)quic_tp_encode(&tp, buf, sizeof buf), 0);

    quic_tp_init_defaults(&tp);
    tp.present = QUIC_TP_F_ACK_DELAY_EXPONENT;
    tp.ack_delay_exponent = 21;
    check_int("encode rejects ack_delay_exponent > 20",
              (long)quic_tp_encode(&tp, buf, sizeof buf), 0);

    quic_tp_init_defaults(&tp);
    tp.present = QUIC_TP_F_MAX_ACK_DELAY;
    tp.max_ack_delay_ms = 16384;
    check_int("encode rejects max_ack_delay >= 2^14",
              (long)quic_tp_encode(&tp, buf, sizeof buf), 0);

    quic_tp_init_defaults(&tp);
    tp.present = QUIC_TP_F_ACTIVE_CONNECTION_ID_LIMIT;
    tp.active_connection_id_limit = 1;
    check_int("encode rejects active_cid_limit < 2",
              (long)quic_tp_encode(&tp, buf, sizeof buf), 0);

    quic_tp_init_defaults(&tp);
    tp.present = QUIC_TP_F_ORIGINAL_DCID;
    tp.original_dcid_len = 21;
    check_int("encode rejects cid_len > 20",
              (long)quic_tp_encode(&tp, buf, sizeof buf), 0);
}

static void test_tp_encode_buffer_overflow(void) {
    printf("== transport params: encode overflow ==\n");
    quic_transport_params_t tp;
    quic_tp_init_defaults(&tp);
    tp.present = QUIC_TP_F_INITIAL_MAX_DATA;
    tp.initial_max_data = 0x3fffffffffffffffULL;  /* needs 8-byte varint */
    uint8_t small[2];
    check_int("encode returns 0 on small buffer",
              (long)quic_tp_encode(&tp, small, sizeof small), 0);
}

/* ============================================================== */
/* CRYPTO-frame stream (rx reassembly + tx chunker)               */
/* ============================================================== */

static void test_crypto_stream_rx_inorder(void) {
    printf("== crypto stream rx: in-order delivery ==\n");
    uint8_t data[64], bm[8];
    quic_crypto_rx_t rx;
    quic_crypto_rx_init(&rx, data, sizeof data, bm, sizeof bm);

    static const uint8_t a[] = { 1,2,3,4 };
    static const uint8_t b[] = { 5,6,7,8 };
    check_int("stage [0..4)",  quic_crypto_rx_stage(&rx, 0, a, sizeof a), 1);
    check_int("contig=4 after a", (long)rx.contig_len, 4);
    check_int("stage [4..8)",  quic_crypto_rx_stage(&rx, 4, b, sizeof b), 1);
    check_int("contig=8 after b", (long)rx.contig_len, 8);

    size_t n = 0;
    const uint8_t* p = quic_crypto_rx_peek(&rx, &n);
    check_int("peek length 8", (long)n, 8);
    static const uint8_t want[] = { 1,2,3,4,5,6,7,8 };
    check_eq("peek bytes", p, want, sizeof want);
    quic_crypto_rx_advance(&rx, 8);
    check_int("post-advance peek empty", quic_crypto_rx_peek(&rx, &n) == NULL, 1);
    check_int("peek out_len after advance", (long)n, 0);
}

static void test_crypto_stream_rx_outoforder(void) {
    printf("== crypto stream rx: out-of-order with gap fill ==\n");
    uint8_t data[64], bm[8];
    quic_crypto_rx_t rx;
    quic_crypto_rx_init(&rx, data, sizeof data, bm, sizeof bm);

    static const uint8_t a[] = { 1,2,3,4 };
    static const uint8_t b[] = { 5,6,7,8 };
    static const uint8_t c[] = { 9,10,11,12 };

    /* Receive last chunk first. */
    check_int("stage [8..12) first", quic_crypto_rx_stage(&rx, 8, c, 4), 1);
    check_int("no contig yet",       (long)rx.contig_len, 0);

    /* Fill the prefix [0..4). */
    check_int("stage [0..4)",        quic_crypto_rx_stage(&rx, 0, a, 4), 1);
    check_int("still no contig until middle filled",
              (long)rx.contig_len, 4);

    /* Fill the middle [4..8) — now everything contiguous. */
    check_int("stage [4..8)",        quic_crypto_rx_stage(&rx, 4, b, 4), 1);
    check_int("contig now 12",       (long)rx.contig_len, 12);
}

static void test_crypto_stream_rx_duplicate(void) {
    printf("== crypto stream rx: duplicate is no-op ==\n");
    uint8_t data[32], bm[4];
    quic_crypto_rx_t rx;
    quic_crypto_rx_init(&rx, data, sizeof data, bm, sizeof bm);

    static const uint8_t a[] = { 0xaa, 0xbb, 0xcc };
    check_int("first stage",     quic_crypto_rx_stage(&rx, 5, a, 3), 1);
    check_int("duplicate stage",  quic_crypto_rx_stage(&rx, 5, a, 3), 0);
    check_int("highest unchanged", (long)rx.highest, 8);
}

static void test_crypto_stream_rx_overlap_conflict(void) {
    printf("== crypto stream rx: conflicting overlap rejected ==\n");
    uint8_t data[32], bm[4];
    quic_crypto_rx_t rx;
    quic_crypto_rx_init(&rx, data, sizeof data, bm, sizeof bm);

    static const uint8_t a[] = { 0x01, 0x02, 0x03 };
    static const uint8_t b[] = { 0x01, 0xff };  /* overlaps at offset 1 */
    check_int("first stage", quic_crypto_rx_stage(&rx, 0, a, 3), 1);
    check_int("conflicting overlap",
              quic_crypto_rx_stage(&rx, 1, b, 2), -1);
}

static void test_crypto_stream_rx_overflow(void) {
    printf("== crypto stream rx: overflow rejected ==\n");
    uint8_t data[8], bm[1];
    quic_crypto_rx_t rx;
    quic_crypto_rx_init(&rx, data, sizeof data, bm, sizeof bm);

    static const uint8_t a[] = { 1,2,3,4 };
    check_int("offset past cap",
              quic_crypto_rx_stage(&rx, 9, a, 1), -1);
    check_int("len past cap",
              quic_crypto_rx_stage(&rx, 6, a, 4), -1);
}

static void test_crypto_stream_rx_partial_consume(void) {
    printf("== crypto stream rx: partial consume preserves remainder ==\n");
    uint8_t data[32], bm[4];
    quic_crypto_rx_t rx;
    quic_crypto_rx_init(&rx, data, sizeof data, bm, sizeof bm);

    static const uint8_t a[] = { 10,20,30,40,50,60,70,80 };
    quic_crypto_rx_stage(&rx, 0, a, 8);
    quic_crypto_rx_advance(&rx, 3);
    size_t n;
    const uint8_t* p = quic_crypto_rx_peek(&rx, &n);
    check_int("remainder len", (long)n, 5);
    static const uint8_t want[] = { 40,50,60,70,80 };
    check_eq("remainder bytes", p, want, 5);

    /* Stage more and ensure peek extends. */
    static const uint8_t b[] = { 90,100 };
    quic_crypto_rx_stage(&rx, 8, b, 2);
    p = quic_crypto_rx_peek(&rx, &n);
    check_int("remainder len after extend", (long)n, 7);
}

static void test_crypto_stream_tx_chunks(void) {
    printf("== crypto stream tx: chunked emission ==\n");
    static const uint8_t msg[10] = { 0,1,2,3,4,5,6,7,8,9 };
    quic_crypto_tx_t tx;
    quic_crypto_tx_init(&tx);
    quic_crypto_tx_set_pending(&tx, msg, sizeof msg);

    uint64_t off; const uint8_t* chunk; size_t len;
    check_int("first chunk avail",
              quic_crypto_tx_next(&tx, 4, &off, &chunk, &len), 1);
    check_int("first offset 0", (long)off, 0);
    check_int("first len 4",    (long)len, 4);
    check_eq("first bytes",     chunk, msg, 4);
    quic_crypto_tx_consume(&tx, len);

    check_int("second chunk avail",
              quic_crypto_tx_next(&tx, 4, &off, &chunk, &len), 1);
    check_int("second offset 4", (long)off, 4);
    check_int("second len 4",    (long)len, 4);
    check_eq("second bytes",     chunk, msg + 4, 4);
    quic_crypto_tx_consume(&tx, len);

    check_int("third chunk avail",
              quic_crypto_tx_next(&tx, 4, &off, &chunk, &len), 1);
    check_int("third offset 8", (long)off, 8);
    check_int("third len 2",    (long)len, 2);  /* only 2 bytes left */
    quic_crypto_tx_consume(&tx, len);

    check_int("no more chunks",
              quic_crypto_tx_next(&tx, 4, &off, &chunk, &len), 0);
    check_int("next_offset advanced", (long)tx.next_offset, 10);
}

static void test_crypto_stream_tx_zero_budget(void) {
    printf("== crypto stream tx: zero MTU yields no chunk ==\n");
    static const uint8_t m[] = {1,2,3};
    quic_crypto_tx_t tx; quic_crypto_tx_init(&tx);
    quic_crypto_tx_set_pending(&tx, m, sizeof m);
    uint64_t off; const uint8_t* p; size_t len;
    check_int("budget 0",
              quic_crypto_tx_next(&tx, 0, &off, &p, &len), 0);
    /* Empty pending */
    quic_crypto_tx_set_pending(&tx, NULL, 0);
    check_int("empty pending",
              quic_crypto_tx_next(&tx, 16, &off, &p, &len), 0);
}

/* ============================================================== */
/* QUIC per-epoch key derivation (RFC 9001 §5.1, §6.1)            */
/* ============================================================== */

static void test_quic_keys_from_initial_secret(void) {
    printf("== QUIC keys: derive from client_initial_secret (RFC 9001 §A.1) ==\n");
    /* Per RFC 9001 §A.1:
     *   client_initial_secret = HKDF-Expand-Label(initial_secret,
     *                              "client in", "", 32) */
    uint8_t secret[32];
    unhex("c00cf151ca5be075ed0ebfb5c80323c4"
          "2d6b7db67881289af4008f1f6c357aea", secret, 32);

    quic_keys_t k;
    int rc = quic_keys_from_secret(secret, 32, 16, 16, &k);
    check_int("derive returns 1", rc, 1);
    check_int("key_len", k.key_len, 16);
    check_int("hp_len",  k.hp_len, 16);

    uint8_t expect[16];
    unhex("1f369613dd76d5467730efcbe3b1a22d", expect, 16);
    check_eq("client quic key", k.key, expect, 16);
    unhex("fa044b2f42a3fd3b46fb255c", expect, 12);
    check_eq("client quic iv",  k.iv,  expect, 12);
    unhex("9f50449e04a0e810283a1e9933adedd2", expect, 16);
    check_eq("client quic hp",  k.hp,  expect, 16);

    /* Also: server_initial_secret per RFC 9001 §A.1. */
    unhex("3c199828fd139efd216c155ad844cc81"
          "fb82fa8d7446fa7d78be803acdda951b", secret, 32);
    rc = quic_keys_from_secret(secret, 32, 16, 16, &k);
    check_int("server derive returns 1", rc, 1);
    unhex("cf3a5331653c364c88f0f379b6067e37", expect, 16);
    check_eq("server quic key", k.key, expect, 16);
    unhex("0ac1493ca1905853b0bba03e", expect, 12);
    check_eq("server quic iv",  k.iv,  expect, 12);
    unhex("c206b8d9b9f0f37644430b490eeaa314", expect, 16);
    check_eq("server quic hp",  k.hp,  expect, 16);
}

static void test_quic_keys_unsupported(void) {
    printf("== QUIC keys: unsupported sizes rejected ==\n");
    uint8_t secret[32] = {0};
    quic_keys_t k;
    memset(&k, 0xa5, sizeof k);
    check_int("rejects key_len=24",
              quic_keys_from_secret(secret, 32, 24, 16, &k), 0);
    check_int("rejects hp_len=24",
              quic_keys_from_secret(secret, 32, 16, 24, &k), 0);
    check_int("rejects secret_len!=32",
              quic_keys_from_secret(secret, 16, 16, 16, &k), 0);
}

static void test_quic_key_update(void) {
    printf("== QUIC key update: §6.1 derives a new secret ==\n");
    uint8_t secret[32];
    unhex("c00cf151ca5be075ed0ebfb5c80323c4"
          "2d6b7db67881289af4008f1f6c357aea", secret, 32);
    uint8_t next[32];
    quic_key_update_next(secret, 32, next);

    /* Property: next != secret, deterministic, non-zero. */
    check_int("next differs from current",
              memcmp(next, secret, 32) != 0, 1);
    int allzero = 1;
    for (int i = 0; i < 32; i++) if (next[i]) { allzero = 0; break; }
    check_int("next is non-zero", !allzero, 1);

    /* Idempotency: same input → same output. */
    uint8_t next2[32];
    quic_key_update_next(secret, 32, next2);
    check_eq("derivation deterministic", next2, next, 32);

    /* Keys derived from the new secret must differ from the old. */
    quic_keys_t k_old, k_new;
    quic_keys_from_secret(secret, 32, 16, 16, &k_old);
    quic_keys_from_secret(next,   32, 16, 16, &k_new);
    check_int("rotated key differs", memcmp(k_new.key, k_old.key, 16) != 0, 1);
    check_int("rotated iv differs",  memcmp(k_new.iv,  k_old.iv,  12) != 0, 1);
    check_int("rotated hp differs",  memcmp(k_new.hp,  k_old.hp,  16) != 0, 1);
}

/* ============================================================== */
/* QUIC↔TLS extension wiring (RFC 9001 §8.2)                      */
/* ============================================================== */

static void test_quic_tls_ext_emit_tp(void) {
    printf("== quic_tls_ext: emit TP TLV ==\n");
    static const uint8_t tp[] = { 0x01, 0x02, 0xaa, 0xbb, 0xcc };
    uint8_t buf[16];
    size_t n = quic_tls_ext_emit_tp(buf, sizeof buf, tp, sizeof tp);
    check_int("emit returns 4 + body_len", (long)n, (long)(4 + sizeof tp));
    check_int("ext_type hi byte", buf[0], 0x00);
    check_int("ext_type lo byte", buf[1], 0x39);
    check_int("ext_len hi byte",  buf[2], 0x00);
    check_int("ext_len lo byte",  buf[3], (long)sizeof tp);
    check_eq("ext_body bytes", buf + 4, tp, sizeof tp);

    /* Empty TP body still emits a valid TLV. */
    n = quic_tls_ext_emit_tp(buf, sizeof buf, NULL, 0);
    check_int("empty body: 4 bytes",  (long)n, 4);
    check_int("empty body: ext_len=0", buf[3], 0);
}

static void test_quic_tls_ext_emit_overflow(void) {
    printf("== quic_tls_ext: emit overflow rejected ==\n");
    static const uint8_t tp[8] = {0};
    uint8_t small[7];
    check_int("buf too small", (long)quic_tls_ext_emit_tp(small, sizeof small, tp, sizeof tp), 0);
    check_int("NULL body with non-zero len rejected",
              (long)quic_tls_ext_emit_tp(small, sizeof small, NULL, 1), 0);
}

static void test_quic_tls_ext_find_tp(void) {
    printf("== quic_tls_ext: find TP in extensions block ==\n");
    /* Build an extensions block with: server_name(0x0000)=empty,
     * QUIC TP(0x0039)=[0xaa,0xbb,0xcc], early_data(0x002a)=empty. */
    uint8_t blk[32];
    size_t off = 0;
    blk[off++] = 0x00; blk[off++] = 0x00;            /* type 0x0000 */
    blk[off++] = 0x00; blk[off++] = 0x00;            /* len 0 */
    blk[off++] = 0x00; blk[off++] = 0x39;            /* QUIC TP */
    blk[off++] = 0x00; blk[off++] = 0x03;            /* len 3 */
    blk[off++] = 0xaa; blk[off++] = 0xbb; blk[off++] = 0xcc;
    blk[off++] = 0x00; blk[off++] = 0x2a;            /* early_data */
    blk[off++] = 0x00; blk[off++] = 0x00;            /* len 0 */

    const uint8_t* body = NULL; size_t blen = 0;
    int rc = quic_tls_ext_find_tp(blk, off, &body, &blen);
    check_int("find returns 1", rc, 1);
    check_int("body length 3", (long)blen, 3);
    static const uint8_t want[] = { 0xaa, 0xbb, 0xcc };
    check_eq("body bytes", body, want, 3);
}

static void test_quic_tls_ext_find_absent(void) {
    printf("== quic_tls_ext: TP absent returns 0 ==\n");
    /* Just one server_name extension, no TP. */
    uint8_t blk[] = { 0x00, 0x00, 0x00, 0x00 };
    const uint8_t* body = NULL; size_t blen = 0;
    int rc = quic_tls_ext_find_tp(blk, sizeof blk, &body, &blen);
    check_int("find returns 0", rc, 0);
    check_int("empty block returns 0",
              quic_tls_ext_find_tp(blk, 0, &body, &blen), 0);
}

static void test_quic_tls_ext_find_truncated(void) {
    printf("== quic_tls_ext: truncated extensions rejected ==\n");
    const uint8_t* body = NULL; size_t blen = 0;
    /* TLV header truncated (3 bytes). */
    uint8_t b1[] = { 0x00, 0x39, 0x00 };
    check_int("truncated header",
              quic_tls_ext_find_tp(b1, sizeof b1, &body, &blen), -1);
    /* TLV body truncated (declared len 5, only 2 follow). */
    uint8_t b2[] = { 0x00, 0x39, 0x00, 0x05, 0xaa, 0xbb };
    check_int("truncated body",
              quic_tls_ext_find_tp(b2, sizeof b2, &body, &blen), -1);
}

static void test_quic_tls_ext_find_duplicate(void) {
    printf("== quic_tls_ext: duplicate TP rejected ==\n");
    uint8_t blk[] = {
        0x00, 0x39, 0x00, 0x01, 0xaa,
        0x00, 0x39, 0x00, 0x01, 0xbb,
    };
    const uint8_t* body = NULL; size_t blen = 0;
    check_int("duplicate TP rejected",
              quic_tls_ext_find_tp(blk, sizeof blk, &body, &blen), -1);
}

static void test_quic_tls_ext_round_trip(void) {
    printf("== quic_tls_ext: emit then find round-trip ==\n");
    /* Encode a real (small) TP set with quic_tp_encode, wrap with
     * quic_tls_ext_emit_tp, then locate and re-decode. */
    quic_transport_params_t tp_in;
    quic_tp_init_defaults(&tp_in);
    tp_in.max_idle_timeout_ms = 30000;
    tp_in.initial_max_data    = 65536;
    tp_in.present = QUIC_TP_F_MAX_IDLE_TIMEOUT | QUIC_TP_F_INITIAL_MAX_DATA;

    uint8_t tp_blob[64];
    size_t tp_len = quic_tp_encode(&tp_in, tp_blob, sizeof tp_blob);
    if (!tp_len) { printf("  FAIL: tp_encode\n"); g_fail++; return; }

    uint8_t ext_block[80];
    size_t  ext_off = 0;
    /* Prepend a non-QUIC dummy extension to make sure scanning works. */
    ext_block[ext_off++] = 0xff; ext_block[ext_off++] = 0xff;
    ext_block[ext_off++] = 0x00; ext_block[ext_off++] = 0x02;
    ext_block[ext_off++] = 0x12; ext_block[ext_off++] = 0x34;

    size_t emitted = quic_tls_ext_emit_tp(ext_block + ext_off,
                                          sizeof ext_block - ext_off,
                                          tp_blob, tp_len);
    check_int("emit succeeded", (long)emitted, (long)(4 + tp_len));
    ext_off += emitted;

    const uint8_t* body = NULL; size_t blen = 0;
    int rc = quic_tls_ext_find_tp(ext_block, ext_off, &body, &blen);
    check_int("find succeeded", rc, 1);
    check_int("body len matches tp_len", (long)blen, (long)tp_len);

    quic_transport_params_t tp_out;
    rc = quic_tp_decode(body, blen, &tp_out);
    check_int("re-decode succeeded", rc, 1);
    check_int("max_idle_timeout_ms preserved",
              (long)tp_out.max_idle_timeout_ms, 30000);
    check_int("initial_max_data preserved",
              (long)tp_out.initial_max_data, 65536);
}

/* ============================================================== */
/* QUIC connection: Initial-epoch rx pump                         */
/* ============================================================== */

static void test_conn_recv_a2_client_initial(void) {
    printf("== conn rx: drive RFC 9001 §A.2 client Initial ==\n");

    quic_conn_t conn;
    quic_conn_init_server(&conn);

    /* Pre-condition: no keys, no peer addrs. */
    check_int("pre: keys not ready", conn.initial_keys_ready, 0);
    check_int("pre: peer addrs unknown", conn.peer_addrs_known, 0);

    uint8_t wire[1500];
    size_t wire_n = unhex(CLIENT_INITIAL_PROTECTED_HEX, wire, sizeof wire);

    int rc = quic_conn_recv_initial(&conn, wire, wire_n);
    check_int("recv_initial returns 0", rc, 0);
    check_int("post: keys derived", conn.initial_keys_ready, 1);
    check_int("post: peer addrs known", conn.peer_addrs_known, 1);
    /* RFC 9001 §A.2: client DCID = 8394c8f03e515708 (8 bytes). SCID
     * is empty per the appendix. */
    check_int("peer_dcid_len 8", (long)conn.peer_dcid_len, 8);
    uint8_t want_dcid[8];
    unhex("8394c8f03e515708", want_dcid, 8);
    check_eq("peer_dcid bytes", conn.peer_dcid, want_dcid, 8);
    check_int("peer_scid_len 0", (long)conn.peer_scid_len, 0);
    check_int("initial_pkts_rcvd 1", (long)conn.initial_pkts_rcvd, 1);
    check_int("initial_ack_eliciting_rcvd 1",
              (long)conn.initial_ack_eliciting_rcvd, 1);
    check_int("initial_crypto_bytes_rcvd 241",
              (long)conn.initial_crypto_bytes_rcvd, 241);

    /* Reassembled CH bytes should be visible in the rx prefix. */
    size_t n = 0;
    const uint8_t* p = quic_conn_initial_rx_peek(&conn, &n);
    check_int("rx peek len 241", (long)n, 241);
    /* TLS 1.3 ClientHello handshake type byte. */
    if (p) check_int("first byte = 0x01 (ClientHello)", p[0], 0x01);

    /* Advance and verify it's empty. */
    quic_conn_initial_rx_advance(&conn, n);
    p = quic_conn_initial_rx_peek(&conn, &n);
    check_int("rx empty after advance", p == NULL, 1);
    check_int("rx peek len 0 after advance", (long)n, 0);
}

static void test_conn_recv_dcid_pin(void) {
    printf("== conn rx: DCID is pinned across packets in same epoch ==\n");

    quic_conn_t conn;
    quic_conn_init_server(&conn);

    uint8_t wire[1500];
    size_t wire_n = unhex(CLIENT_INITIAL_PROTECTED_HEX, wire, sizeof wire);
    check_int("first packet ok",
              quic_conn_recv_initial(&conn, wire, wire_n), 0);

    /* Mutate the DCID byte in the second copy and retry — should fail. */
    uint8_t wire2[1500];
    memcpy(wire2, wire, wire_n);
    /* DCID starts at offset 6 (byte0 + version[4] + dcid_len[1]). */
    wire2[6] ^= 0xff;
    check_int("second packet with different DCID rejected",
              quic_conn_recv_initial(&conn, wire2, wire_n), -1);
}

static void test_conn_recv_rejects_short_garbage(void) {
    printf("== conn rx: garbage / short / bad version rejected ==\n");
    quic_conn_t conn;
    quic_conn_init_server(&conn);
    uint8_t junk[3] = { 0xff, 0xff, 0xff };
    check_int("too short", quic_conn_recv_initial(&conn, junk, sizeof junk), -1);

    /* 7-byte buffer with non-long-header byte0. */
    uint8_t bad_hdr[16] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    check_int("short-header rejected",
              quic_conn_recv_initial(&conn, bad_hdr, sizeof bad_hdr), -1);

    /* Long-header but version 0 (version negotiation) — rejected as
     * non-Initial. */
    uint8_t vn[16] = { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    check_int("version 0 rejected",
              quic_conn_recv_initial(&conn, vn, sizeof vn), -1);

    /* Long-header Initial form but wrong version. */
    uint8_t bad_ver[16] = { 0xc0, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00 };
    check_int("wrong version rejected",
              quic_conn_recv_initial(&conn, bad_ver, sizeof bad_ver), -1);

    /* Type bits != Initial (0x10 = Handshake). */
    uint8_t hs[16] = { 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    check_int("non-Initial long header rejected",
              quic_conn_recv_initial(&conn, hs, sizeof hs), -1);
}

static void test_conn_recv_rejects_aead_failure(void) {
    printf("== conn rx: AEAD failure rejected ==\n");
    quic_conn_t conn;
    quic_conn_init_server(&conn);
    uint8_t wire[1500];
    size_t wire_n = unhex(CLIENT_INITIAL_PROTECTED_HEX, wire, sizeof wire);
    /* Flip a byte deep in the protected payload (well past the
     * header so HP-mask sample isn't disturbed in a way that
     * randomly succeeds). */
    wire[wire_n - 30] ^= 0x01;
    check_int("AEAD-corrupted Initial rejected",
              quic_conn_recv_initial(&conn, wire, wire_n), -1);
    /* Keys should have been derived even though AEAD failed,
     * because we derived them from the visible DCID before
     * attempting decryption. peer_addrs likewise. */
    check_int("keys still derived from header DCID",
              conn.initial_keys_ready, 1);
    check_int("no Initial counted",
              (long)conn.initial_pkts_rcvd, 0);
}

/* ---------------- phase 5e2: ClientHello + TP extraction -------------- */

static void w8 (uint8_t** p, uint8_t  v) { (*p)[0] = v; *p += 1; }
static void w16(uint8_t** p, uint16_t v) { (*p)[0] = v >> 8; (*p)[1] = (uint8_t)v; *p += 2; }
static void w24(uint8_t** p, uint32_t v) { (*p)[0] = v >> 16; (*p)[1] = v >> 8; (*p)[2] = (uint8_t)v; *p += 3; }
static void wb (uint8_t** p, const void* s, size_t n) { memcpy(*p, s, n); *p += n; }

/* Build a synthetic CH into `out`. If `tp_blob` != NULL, splice a
 * quic_transport_parameters extension (codepoint 0x0039) as the LAST
 * non-PSK extension. Returns total bytes written. */
static size_t build_synthetic_ch(uint8_t* out, size_t cap,
                                 const uint8_t* tp_blob, size_t tp_len)
{
    (void)cap;
    uint8_t* p = out;
    /* Handshake header: type=0x01, len placeholder backfilled later. */
    w8(&p, 0x01);
    uint8_t* hs_len_at = p; w24(&p, 0);
    uint8_t* hs_body = p;

    w16(&p, 0x0303);                                        /* legacy_version */
    for (int i = 0; i < 32; i++) w8(&p, (uint8_t)(0x40 + i)); /* random */
    w8(&p, 0);                                              /* legacy_session_id len = 0 */
    /* cipher_suites: TLS_CHACHA20_POLY1305_SHA256 */
    w16(&p, 2);
    w16(&p, 0x1303);
    /* legacy_compression_methods: [0x00] */
    w8(&p, 1); w8(&p, 0);

    /* extensions block, length backfilled. */
    uint8_t* ext_len_at = p; w16(&p, 0);
    uint8_t* ext_start = p;

    /* supported_versions: 0x0304 */
    w16(&p, 0x002b); w16(&p, 1 + 2); w8(&p, 2); w16(&p, 0x0304);
    /* supported_groups: x25519 */
    w16(&p, 0x000a); w16(&p, 4); w16(&p, 2); w16(&p, 0x001d);
    /* key_share: x25519 with a 32-byte pubkey */
    w16(&p, 0x0033); w16(&p, 2 + 4 + 32); w16(&p, 4 + 32);
    w16(&p, 0x001d); w16(&p, 32);
    for (int i = 0; i < 32; i++) w8(&p, (uint8_t)(0x80 + i));
    /* signature_algorithms: ed25519 (0x0807) */
    w16(&p, 0x000d); w16(&p, 4); w16(&p, 2); w16(&p, 0x0807);
    /* QUIC transport_parameters: codepoint 0x0039, body = tp_blob */
    if (tp_blob != NULL) {
        w16(&p, 0x0039);
        w16(&p, (uint16_t)tp_len);
        wb (&p, tp_blob, tp_len);
    }

    uint16_t ext_len = (uint16_t)(p - ext_start);
    ext_len_at[0] = ext_len >> 8; ext_len_at[1] = (uint8_t)ext_len;
    uint32_t hs_body_len = (uint32_t)(p - hs_body);
    hs_len_at[0] = (uint8_t)(hs_body_len >> 16);
    hs_len_at[1] = (uint8_t)(hs_body_len >> 8);
    hs_len_at[2] = (uint8_t)hs_body_len;

    return (size_t)(p - out);
}

static size_t make_sample_tp(uint8_t* out, size_t cap)
{
    quic_transport_params_t tp;
    quic_tp_init_defaults(&tp);
    tp.present |= QUIC_TP_F_MAX_IDLE_TIMEOUT;
    tp.max_idle_timeout_ms = 30000;
    tp.present |= QUIC_TP_F_INITIAL_MAX_DATA;
    tp.initial_max_data = 1048576;
    tp.present |= QUIC_TP_F_INITIAL_MAX_STREAMS_BIDI;
    tp.initial_max_streams_bidi = 100;
    tp.present |= QUIC_TP_F_INITIAL_SOURCE_CID;
    static const uint8_t cid[] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    memcpy(tp.initial_source_cid, cid, sizeof cid);
    tp.initial_source_cid_len = (uint8_t)sizeof cid;
    return quic_tp_encode(&tp, out, cap);
}

static void test_conn_extract_ch_with_tp(void) {
    printf("== conn: extract CH + QUIC transport params ==\n");

    uint8_t tp_blob[256];
    size_t tp_len = make_sample_tp(tp_blob, sizeof tp_blob);
    if (tp_len == 0) { printf("  FAIL: tp encode\n"); g_fail++; return; }

    uint8_t ch[1024];
    size_t ch_len = build_synthetic_ch(ch, sizeof ch, tp_blob, tp_len);

    quic_conn_t conn;
    quic_conn_init_server(&conn);
    /* Stage the CH bytes directly into the Initial-epoch rx stream. */
    if (quic_crypto_rx_stage(&conn.rx_initial, 0, ch, ch_len) < 0) {
        printf("  FAIL: rx stage\n"); g_fail++; return;
    }

    tls13_client_hello_t parsed;
    quic_transport_params_t peer_tp;
    int rc = quic_conn_initial_extract_client_hello(&conn, &parsed, &peer_tp);
    check_int("extract returns 1", rc, 1);
    check_int("CH offers chacha_poly", parsed.offers_chacha_poly, 1);
    check_int("CH offers tls13",       parsed.offers_tls13, 1);
    check_int("CH offers x25519",      parsed.offers_x25519, 1);

    check_int("peer_tp has max_idle_timeout",
              (peer_tp.present & QUIC_TP_F_MAX_IDLE_TIMEOUT) != 0, 1);
    check_int("peer_tp.max_idle_timeout_ms == 30000",
              (long)peer_tp.max_idle_timeout_ms, 30000);
    check_int("peer_tp.initial_max_data == 1048576",
              (long)peer_tp.initial_max_data, 1048576);
    check_int("peer_tp.initial_max_streams_bidi == 100",
              (long)peer_tp.initial_max_streams_bidi, 100);
    check_int("peer_tp has initial_source_cid",
              (peer_tp.present & QUIC_TP_F_INITIAL_SOURCE_CID) != 0, 1);
    check_int("peer_tp.initial_source_cid_len == 8",
              (long)peer_tp.initial_source_cid_len, 8);
    check_int("peer_tp.initial_source_cid bytes match",
              memcmp(peer_tp.initial_source_cid,
                     "\x11\x22\x33\x44\x55\x66\x77\x88", 8) == 0, 1);

    /* parsed.raw must alias the rx buffer. */
    check_int("parsed.raw aliases rx",
              parsed.raw == conn.rx_initial_data, 1);
    check_int("parsed.raw_len == ch_len",
              (long)parsed.raw_len, (long)ch_len);
}

static void test_conn_extract_ch_incomplete(void) {
    printf("== conn: extract CH returns 0 when incomplete ==\n");
    uint8_t tp_blob[256];
    size_t tp_len = make_sample_tp(tp_blob, sizeof tp_blob);
    uint8_t ch[1024];
    size_t ch_len = build_synthetic_ch(ch, sizeof ch, tp_blob, tp_len);

    quic_conn_t conn;
    quic_conn_init_server(&conn);
    /* Stage only a prefix — header + a few body bytes. */
    if (quic_crypto_rx_stage(&conn.rx_initial, 0, ch, 32) < 0) {
        printf("  FAIL: rx stage prefix\n"); g_fail++; return;
    }

    tls13_client_hello_t parsed;
    quic_transport_params_t peer_tp;
    check_int("incomplete CH returns 0",
              quic_conn_initial_extract_client_hello(&conn, &parsed, &peer_tp), 0);

    /* Now stage the rest. */
    if (quic_crypto_rx_stage(&conn.rx_initial, 32, ch + 32, ch_len - 32) < 0) {
        printf("  FAIL: rx stage tail\n"); g_fail++; return;
    }
    check_int("complete CH then returns 1",
              quic_conn_initial_extract_client_hello(&conn, &parsed, &peer_tp), 1);
}

static void test_conn_extract_ch_missing_tp(void) {
    printf("== conn: extract CH without QUIC TP rejected ==\n");
    uint8_t ch[1024];
    /* No TP extension. */
    size_t ch_len = build_synthetic_ch(ch, sizeof ch, NULL, 0);

    quic_conn_t conn;
    quic_conn_init_server(&conn);
    if (quic_crypto_rx_stage(&conn.rx_initial, 0, ch, ch_len) < 0) {
        printf("  FAIL: rx stage\n"); g_fail++; return;
    }

    tls13_client_hello_t parsed;
    quic_transport_params_t peer_tp;
    check_int("missing QUIC TP returns -1",
              quic_conn_initial_extract_client_hello(&conn, &parsed, &peer_tp), -1);
}

static void test_conn_extract_ch_malformed_tp(void) {
    printf("== conn: extract CH with malformed TP rejected ==\n");
    /* TP blob that decodes to truncated TLV: id=0x01 (varint, 1 byte),
     * len=0x08 (claims 8-byte body), but only 2 bytes follow. */
    uint8_t bad_tp[] = { 0x01, 0x08, 0xaa, 0xbb };

    uint8_t ch[1024];
    size_t ch_len = build_synthetic_ch(ch, sizeof ch, bad_tp, sizeof bad_tp);

    quic_conn_t conn;
    quic_conn_init_server(&conn);
    if (quic_crypto_rx_stage(&conn.rx_initial, 0, ch, ch_len) < 0) {
        printf("  FAIL: rx stage\n"); g_fail++; return;
    }

    tls13_client_hello_t parsed;
    quic_transport_params_t peer_tp;
    check_int("malformed TP returns -1",
              quic_conn_initial_extract_client_hello(&conn, &parsed, &peer_tp), -1);
}

static void test_conn_extract_ch_not_handshake_type(void) {
    printf("== conn: extract CH rejects non-CH handshake type ==\n");
    /* Build a valid CH but flip the handshake type to 0x02 (server_hello). */
    uint8_t tp_blob[256];
    size_t tp_len = make_sample_tp(tp_blob, sizeof tp_blob);
    uint8_t ch[1024];
    size_t ch_len = build_synthetic_ch(ch, sizeof ch, tp_blob, tp_len);
    ch[0] = 0x02;

    quic_conn_t conn;
    quic_conn_init_server(&conn);
    if (quic_crypto_rx_stage(&conn.rx_initial, 0, ch, ch_len) < 0) {
        printf("  FAIL: rx stage\n"); g_fail++; return;
    }
    tls13_client_hello_t parsed;
    quic_transport_params_t peer_tp;
    check_int("non-CH type returns -1",
              quic_conn_initial_extract_client_hello(&conn, &parsed, &peer_tp), -1);
}

/* ---------------- phase 5e3: outbound Initial emission --------------- */

/* Drive the §A.2 client Initial through a server conn so peer_dcid/
 * peer_scid are populated (this is the standard fixture for emit
 * tests). */
static void server_conn_after_a2(quic_conn_t* conn)
{
    quic_conn_init_server(conn);
    uint8_t wire[1500];
    size_t wn = unhex(CLIENT_INITIAL_PROTECTED_HEX, wire, sizeof wire);
    if (quic_conn_recv_initial(conn, wire, wn) != 0) {
        printf("  FATAL: §A.2 setup failed\n"); exit(2);
    }
}

static void test_conn_emit_initial_basic(void) {
    printf("== conn: emit Initial — basic round-trip ==\n");
    quic_conn_t conn;
    server_conn_after_a2(&conn);

    /* Server picks an SCID. */
    static const uint8_t our_scid[] = {0xf0,0x67,0xa5,0x50,0x2a,0x42,0x62,0xb5};
    quic_conn_set_our_scid(&conn, our_scid, sizeof our_scid);

    /* Pretend the TLS layer produced a fake handshake blob. */
    uint8_t fake_sh[200];
    for (size_t i = 0; i < sizeof fake_sh; i++) fake_sh[i] = (uint8_t)(0xa0 + (i & 0x3f));
    quic_conn_initial_tx_set_pending(&conn, fake_sh, sizeof fake_sh);

    uint8_t out[2048];
    size_t n = quic_conn_emit_initial(&conn, out, sizeof out);
    check_int("emit produced bytes", n > 0, 1);
    check_int("tx keys derived",     conn.initial_tx_keys_ready, 1);
    check_int("pn incremented",      (long)conn.initial_tx_next_pn, 1);

    /* Decrypt the emitted packet using the client-side keys for the
     * *server* direction (i.e. is_server=1 derived from peer_dcid). */
    quic_initial_keys_t client_view;
    quic_initial_derive(conn.peer_dcid, conn.peer_dcid_len,
                        /*is_server=*/1, &client_view);

    quic_initial_pkt_t parsed;
    uint8_t scratch[2048];
    int rc = quic_initial_parse(out, n, &client_view,
                                &parsed, scratch, sizeof scratch);
    check_int("emitted Initial parses", rc, 0);
    check_int("parsed pn", (long)parsed.pn, 0);
    check_int("parsed dcid_len matches peer_scid_len",
              (long)parsed.dcid_len, (long)conn.peer_scid_len);
    check_int("parsed scid_len matches our_scid_len",
              (long)parsed.scid_len, (long)sizeof our_scid);
    check_int("parsed scid bytes match our_scid",
              memcmp(parsed.scid, our_scid, sizeof our_scid) == 0, 1);

    /* Walk frames; expect a CRYPTO frame at offset 0 carrying part of
     * (or all of) fake_sh. */
    quic_frame_t f;
    size_t consumed = quic_frame_decode(parsed.payload, parsed.payload_len, &f);
    check_int("first frame decodes", consumed > 0 && consumed != QUIC_FRAME_DECODE_ERROR, 1);
    check_int("first frame is CRYPTO", f.type == QUIC_FT_CRYPTO, 1);
    check_int("CRYPTO offset == 0", (long)f.u.crypto.offset, 0);
    check_int("CRYPTO bytes match fake_sh prefix",
              memcmp(f.u.crypto.data, fake_sh, (size_t)f.u.crypto.length) == 0, 1);

    /* tx cursor advanced by the chunk length. */
    check_int("tx_initial.next_offset advanced",
              (long)conn.tx_initial.next_offset, (long)f.u.crypto.length);
}

static void test_conn_emit_initial_chunks(void) {
    printf("== conn: emit Initial — multi-packet chunking ==\n");
    quic_conn_t conn;
    server_conn_after_a2(&conn);
    static const uint8_t scid[] = {0xaa,0xbb,0xcc,0xdd};
    quic_conn_set_our_scid(&conn, scid, sizeof scid);

    /* A larger pending blob than fits in any single packet of the
     * cap below, to force >1 emission. */
    uint8_t big[1024];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i ^ 0x5a);
    quic_conn_initial_tx_set_pending(&conn, big, sizeof big);

    uint8_t out[300];   /* tiny cap → forces fragmentation */
    size_t total_emitted_payload = 0;
    int packets = 0;
    while (1) {
        size_t n = quic_conn_emit_initial(&conn, out, sizeof out);
        if (n == 0) break;
        packets++;

        quic_initial_keys_t cv;
        quic_initial_derive(conn.peer_dcid, conn.peer_dcid_len, 1, &cv);
        quic_initial_pkt_t pp;
        uint8_t s[1024];
        if (quic_initial_parse(out, n, &cv, &pp, s, sizeof s) != 0) {
            printf("  FAIL: chunked Initial #%d parse\n", packets); g_fail++; return;
        }
        quic_frame_t f;
        size_t c = quic_frame_decode(pp.payload, pp.payload_len, &f);
        if (c == 0 || c == QUIC_FRAME_DECODE_ERROR || f.type != QUIC_FT_CRYPTO) {
            printf("  FAIL: chunked frame #%d\n", packets); g_fail++; return;
        }
        if ((uint64_t)f.u.crypto.offset != total_emitted_payload) {
            printf("  FAIL: chunked offset mismatch (%llu vs %zu)\n",
                   (unsigned long long)f.u.crypto.offset, total_emitted_payload);
            g_fail++; return;
        }
        if (memcmp(f.u.crypto.data, big + total_emitted_payload,
                   (size_t)f.u.crypto.length) != 0) {
            printf("  FAIL: chunked bytes mismatch\n"); g_fail++; return;
        }
        total_emitted_payload += (size_t)f.u.crypto.length;
        if (packets > 50) { printf("  FAIL: runaway loop\n"); g_fail++; return; }
    }

    check_int("multiple packets emitted", packets > 1, 1);
    check_int("all bytes emitted", (long)total_emitted_payload, (long)sizeof big);
    check_int("pn counter == packets", (long)conn.initial_tx_next_pn, (long)packets);
}

static void test_conn_emit_initial_no_pending(void) {
    printf("== conn: emit Initial returns 0 with no pending ==\n");
    quic_conn_t conn;
    server_conn_after_a2(&conn);
    static const uint8_t scid[] = {0x01,0x02};
    quic_conn_set_our_scid(&conn, scid, sizeof scid);
    uint8_t out[2048];
    check_int("no pending → 0", (long)quic_conn_emit_initial(&conn, out, sizeof out), 0);
    check_int("pn unchanged",   (long)conn.initial_tx_next_pn, 0);
}

static void test_conn_emit_initial_no_peer_addrs(void) {
    printf("== conn: emit Initial requires peer addrs ==\n");
    quic_conn_t conn;
    quic_conn_init_server(&conn);   /* fresh — no recv yet */
    uint8_t fake[16] = {0};
    quic_conn_initial_tx_set_pending(&conn, fake, sizeof fake);
    uint8_t out[2048];
    check_int("no peer addrs → 0",
              (long)quic_conn_emit_initial(&conn, out, sizeof out), 0);
}

/* ---------------- phase 5e4: Handshake packet build/parse ----------- */

static void test_handshake_pkt_round_trip(void) {
    printf("== Handshake packet build/parse round-trip ==\n");

    /* Use a deterministic 32-byte handshake_traffic_secret to derive
     * AES-128-GCM keys via the RFC 9001 §5.1 label set ("quic key" /
     * "quic iv" / "quic hp"). Reusing quic_keys_from_secret which we
     * built in phase 5c. */
    uint8_t secret[32];
    for (int i = 0; i < 32; i++) secret[i] = (uint8_t)(0x10 + i);
    quic_keys_t k;
    if (quic_keys_from_secret(secret, sizeof secret, 16, 16, &k) != 1) {
        printf("  FAIL: derive keys\n"); g_fail++; return;
    }
    /* Project into the Initial-keys-shaped struct used by the packet API. */
    quic_handshake_keys_t keys;
    memcpy(keys.key, k.key, 16);
    memcpy(keys.iv,  k.iv,  12);
    memcpy(keys.hp,  k.hp,  16);

    /* Some plaintext frames — a CRYPTO frame at offset 0 with arbitrary bytes. */
    uint8_t hs_bytes[80];
    for (size_t i = 0; i < sizeof hs_bytes; i++) hs_bytes[i] = (uint8_t)(0x70 + (i & 0x1f));
    uint8_t frames[256];
    size_t fn = quic_frame_crypto_encode(frames, sizeof frames, 0,
                                         hs_bytes, sizeof hs_bytes);
    if (fn == 0) { printf("  FAIL: crypto encode\n"); g_fail++; return; }

    quic_handshake_pkt_t pkt = {0};
    pkt.version = 0x00000001u;
    static const uint8_t dcid[] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    static const uint8_t scid[] = {0xaa,0xbb,0xcc,0xdd};
    memcpy(pkt.dcid, dcid, sizeof dcid); pkt.dcid_len = sizeof dcid;
    memcpy(pkt.scid, scid, sizeof scid); pkt.scid_len = sizeof scid;
    pkt.pn = 42;
    pkt.pn_len = 2;
    pkt.payload = frames;
    pkt.payload_len = fn;

    uint8_t wire[2048];
    size_t n = quic_handshake_build(wire, sizeof wire, &pkt, &keys);
    check_int("build produced bytes", n > 0, 1);
    /* Long header + Handshake type bits = byte0 high nibble == 0xe? */
    check_int("byte0 long-header form bit", (wire[0] & 0x80) != 0, 1);
    /* After HP the type bits might still be visible (HP only masks
     * low 4 bits): top 4 bits should be 1110 = 0xE for Handshake. */
    check_int("byte0 type bits == Handshake (0xe0)",
              (wire[0] & 0xf0) == 0xe0, 1);

    quic_handshake_pkt_t got;
    uint8_t scratch[2048];
    int rc = quic_handshake_parse(wire, n, &keys, &got, scratch, sizeof scratch);
    check_int("parse returns 0", rc, 0);
    check_int("dcid matches", memcmp(got.dcid, dcid, sizeof dcid) == 0
                              && got.dcid_len == sizeof dcid, 1);
    check_int("scid matches", memcmp(got.scid, scid, sizeof scid) == 0
                              && got.scid_len == sizeof scid, 1);
    check_int("pn matches", (long)got.pn, 42);
    check_int("pn_len matches", (long)got.pn_len, 2);
    check_int("payload_len matches", (long)got.payload_len, (long)fn);
    check_int("payload bytes match",
              memcmp(got.payload, frames, fn) == 0, 1);

    /* Walk the decoded payload and verify CRYPTO frame contents. */
    quic_frame_t f;
    size_t consumed = quic_frame_decode(got.payload, got.payload_len, &f);
    check_int("inner CRYPTO frame decodes",
              consumed > 0 && consumed != QUIC_FRAME_DECODE_ERROR
              && f.type == QUIC_FT_CRYPTO, 1);
    check_int("inner CRYPTO bytes match",
              memcmp(f.u.crypto.data, hs_bytes, sizeof hs_bytes) == 0, 1);
}

static void test_handshake_pkt_rejects_initial_type(void) {
    printf("== Handshake parser rejects Initial-typed packet ==\n");
    /* Build a real Initial packet, then feed it to handshake_parse. */
    uint8_t dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_initial_keys_t ikeys;
    quic_initial_derive(dcid, sizeof dcid, /*is_server=*/0, &ikeys);

    uint8_t frames[16];
    size_t fn = quic_frame_padding_encode(frames, sizeof frames, 16);
    quic_initial_pkt_t ip = {0};
    ip.version = 0x00000001u;
    memcpy(ip.dcid, dcid, sizeof dcid); ip.dcid_len = sizeof dcid;
    ip.pn = 0; ip.pn_len = 2;
    ip.payload = frames; ip.payload_len = fn;
    uint8_t wire[2048];
    size_t n = quic_initial_build(wire, sizeof wire, &ip, &ikeys, 0);
    if (n == 0) { printf("  FAIL: build initial\n"); g_fail++; return; }

    quic_handshake_pkt_t got;
    uint8_t scratch[2048];
    /* Use bogus handshake keys — type check should fail before AEAD. */
    quic_handshake_keys_t hks; memset(&hks, 0, sizeof hks);
    check_int("Initial-typed packet rejected by handshake_parse",
              quic_handshake_parse(wire, n, &hks, &got, scratch, sizeof scratch),
              -1);
}

static void test_handshake_pkt_rejects_bad_version(void) {
    printf("== Handshake parser rejects wrong version ==\n");
    uint8_t secret[32]; for (int i = 0; i < 32; i++) secret[i] = (uint8_t)i;
    quic_keys_t k;
    quic_keys_from_secret(secret, 32, 16, 16, &k);
    quic_handshake_keys_t keys;
    memcpy(keys.key, k.key, 16);
    memcpy(keys.iv,  k.iv,  12);
    memcpy(keys.hp,  k.hp,  16);

    uint8_t pad[8]; memset(pad, 0, sizeof pad);
    quic_handshake_pkt_t pkt = {0};
    pkt.version = 0x00000001u;
    pkt.pn = 0; pkt.pn_len = 1;
    pkt.payload = pad; pkt.payload_len = sizeof pad;
    uint8_t wire[256];
    size_t n = quic_handshake_build(wire, sizeof wire, &pkt, &keys);
    if (n == 0) { printf("  FAIL: build hs\n"); g_fail++; return; }

    /* Corrupt the version field to 0xdeadbeef. */
    wire[1] = 0xde; wire[2] = 0xad; wire[3] = 0xbe; wire[4] = 0xef;

    quic_handshake_pkt_t got;
    uint8_t scratch[256];
    check_int("wrong version rejected",
              quic_handshake_parse(wire, n, &keys, &got, scratch, sizeof scratch),
              -1);
}

/* ---------------- phase 5e5: handshake-epoch on conn ----------------- */

/* Helper: install matched handshake secrets on a server conn so it can
 * encrypt/decrypt against itself (we synthesize a "client" conn with
 * the secrets swapped). */
static void install_matched_hs_secrets(quic_conn_t* server,
                                       quic_conn_t* client_view)
{
    static const uint8_t s_secret[32] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
        0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,0x01,
    };
    static const uint8_t c_secret[32] = {
        0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,0x18,
        0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90,
        0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,
        0x89,0x9a,0xab,0xbc,0xcd,0xde,0xef,0xf0,
    };
    /* server sends with s_secret, receives with c_secret. */
    if (quic_conn_install_handshake_secrets(server,
                                            s_secret, c_secret, 32) != 0) {
        printf("  FATAL: hs install (server)\n"); exit(2);
    }
    if (client_view) {
        /* client view receives with s_secret, sends with c_secret. */
        if (quic_conn_install_handshake_secrets(client_view,
                                                c_secret, s_secret, 32) != 0) {
            printf("  FATAL: hs install (client)\n"); exit(2);
        }
    }
}

static void test_conn_install_handshake_secrets(void) {
    printf("== conn: install handshake secrets ==\n");
    quic_conn_t conn;
    quic_conn_init_server(&conn);
    install_matched_hs_secrets(&conn, NULL);
    check_int("hs keys ready", conn.handshake_keys_ready, 1);
    check_int("rx and tx differ",
              memcmp(conn.handshake_tx_keys.key,
                     conn.handshake_rx_keys.key, 16) != 0, 1);
}

static void test_conn_install_handshake_secrets_idempotent(void) {
    printf("== conn: install handshake secrets — idempotent ==\n");
    quic_conn_t conn;
    quic_conn_init_server(&conn);
    install_matched_hs_secrets(&conn, NULL);
    uint8_t saved[16]; memcpy(saved, conn.handshake_tx_keys.key, 16);
    install_matched_hs_secrets(&conn, NULL);
    check_int("keys unchanged", memcmp(saved, conn.handshake_tx_keys.key, 16), 0);
}

static void test_conn_emit_handshake_round_trip(void) {
    printf("== conn: emit Handshake — round-trip via peer view ==\n");
    quic_conn_t server, client;
    server_conn_after_a2(&server);
    quic_conn_init_server(&client);
    /* Mirror peer addrs so the client view's recv path is happy. */
    install_matched_hs_secrets(&server, &client);

    static const uint8_t our_scid[] = {
        0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7
    };
    quic_conn_set_our_scid(&server, our_scid, sizeof our_scid);

    /* On the receiving (client) view, we need DCID+SCID set so we
     * decode against the same fields the server sends. The server
     * uses peer_scid (from §A.2 client) as the wire DCID, and our_scid
     * as SCID. The client view doesn't actually run quic_conn_recv_*
     * for headers — quic_handshake_parse only needs the keys. So we
     * decrypt with our installed handshake_rx_keys directly. */

    uint8_t blob[400];
    for (size_t i = 0; i < sizeof blob; i++) blob[i] = (uint8_t)(i * 7 + 3);
    quic_conn_handshake_tx_set_pending(&server, blob, sizeof blob);

    uint8_t out[1500];
    size_t n = quic_conn_emit_handshake(&server, out, sizeof out);
    check_int("emit produced bytes", n > 0, 1);
    check_int("hs tx pn incremented",
              (long)server.handshake_tx_next_pn, 1);

    /* Decrypt via client_view's rx keys (= server's tx). */
    quic_handshake_pkt_t got;
    uint8_t scratch[1500];
    int rc = quic_handshake_parse(out, n, &client.handshake_rx_keys,
                                  &got, scratch, sizeof scratch);
    check_int("client decrypt OK", rc, 0);
    check_int("type=Handshake (0xE0 high nibble)",
              (out[0] & 0xf0) == 0xe0 ? 0 : 1, 0);
    check_int("payload non-empty", got.payload_len > 0, 1);
}

static void test_conn_emit_handshake_no_keys(void) {
    printf("== conn: emit Handshake — no keys, no emit ==\n");
    quic_conn_t conn;
    server_conn_after_a2(&conn);
    static const uint8_t scid[] = {1,2,3,4,5,6,7,8};
    quic_conn_set_our_scid(&conn, scid, sizeof scid);
    uint8_t blob[64]; memset(blob, 0x55, sizeof blob);
    quic_conn_handshake_tx_set_pending(&conn, blob, sizeof blob);
    uint8_t out[1500];
    check_int("no keys → 0", (long)quic_conn_emit_handshake(&conn, out, sizeof out), 0);
}

static void test_conn_recv_handshake_round_trip(void) {
    printf("== conn: recv Handshake — pulls CRYPTO bytes ==\n");
    quic_conn_t server, client;
    server_conn_after_a2(&server);
    quic_conn_init_server(&client);
    install_matched_hs_secrets(&server, &client);
    /* Client view needs the same peer addrs to *send* (we make it
     * symmetric by feeding it the same setup). */
    /* For this test we just exercise server.emit → server.recv
     * (via the matching key on server side after we swap). */

    static const uint8_t scid[] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
    quic_conn_set_our_scid(&server, scid, sizeof scid);

    static const uint8_t crypto[] = {
        0xc0,0xff,0xee,0x42,0x13,0x37,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,
    };
    quic_conn_handshake_tx_set_pending(&server, crypto, sizeof crypto);

    uint8_t out[1500];
    size_t n = quic_conn_emit_handshake(&server, out, sizeof out);
    if (n == 0) { printf("  FAIL: emit 0\n"); g_fail++; return; }

    /* Feed into the client view's recv pump. */
    int rc = quic_conn_recv_handshake(&client, out, n);
    check_int("recv OK", rc, 0);
    check_int("hs pkts++", (long)client.handshake_pkts_rcvd, 1);
    check_int("crypto bytes accounted",
              (long)client.handshake_crypto_bytes_rcvd, (long)sizeof crypto);

    size_t avail = 0;
    const uint8_t* p = quic_conn_handshake_rx_peek(&client, &avail);
    check_int("rx avail equals crypto len", (long)avail, (long)sizeof crypto);
    if (p) check_int("rx bytes match", memcmp(p, crypto, sizeof crypto), 0);
}

static void test_conn_recv_handshake_rejects_initial_type(void) {
    printf("== conn: recv Handshake — rejects Initial-type byte ==\n");
    quic_conn_t conn;
    quic_conn_init_server(&conn);
    install_matched_hs_secrets(&conn, NULL);
    uint8_t fake[64]; memset(fake, 0, sizeof fake);
    fake[0] = 0xc0; /* long+fixed, type=00 (Initial) */
    fake[1] = 0; fake[2] = 0; fake[3] = 0; fake[4] = 1;
    check_int("Initial type rejected",
              quic_conn_recv_handshake(&conn, fake, sizeof fake), -1);
}

static void test_conn_recv_handshake_rejects_no_keys(void) {
    printf("== conn: recv Handshake — no keys → -1 ==\n");
    quic_conn_t conn;
    quic_conn_init_server(&conn);
    uint8_t fake[64]; memset(fake, 0, sizeof fake);
    fake[0] = 0xe0;
    check_int("no keys → -1",
              quic_conn_recv_handshake(&conn, fake, sizeof fake), -1);
}

/* ============================================================== */

/* ---------------- phase 5e6: server handshake driver ----------------- */

#include "../quic/handshake_driver.h"
#include "../crypto/x25519.h"

static void drive_test_setup_conn_with_ch(quic_conn_t* conn,
                                          const uint8_t* tp_blob,
                                          size_t tp_len,
                                          uint8_t* ch_buf, size_t ch_buf_cap,
                                          size_t* ch_len_out)
{
    quic_conn_init_server(conn);
    size_t ch_len = build_synthetic_ch(ch_buf, ch_buf_cap, tp_blob, tp_len);
    if (quic_crypto_rx_stage(&conn->rx_initial, 0, ch_buf, ch_len) < 0) {
        printf("  FATAL: rx stage\n"); exit(2);
    }
    /* Pretend the embedder ran recv_initial: fake peer dcid/scid +
     * peer_addrs_known so the tx pipelines can derive Initial keys. */
    static const uint8_t peer_dcid[] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8};
    static const uint8_t peer_scid[] = {0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8};
    quic_conn_force_derive_initial_keys(conn, peer_dcid, sizeof peer_dcid);
    memcpy(conn->peer_dcid, peer_dcid, sizeof peer_dcid);
    conn->peer_dcid_len = sizeof peer_dcid;
    memcpy(conn->peer_scid, peer_scid, sizeof peer_scid);
    conn->peer_scid_len = sizeof peer_scid;
    conn->peer_addrs_known = 1;
    static const uint8_t our_scid[] = {0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7};
    quic_conn_set_our_scid(conn, our_scid, sizeof our_scid);
    *ch_len_out = ch_len;
}

static void test_drive_server_handshake_happy(void) {
    printf("== drive: full server handshake (CH → SH+EE+Cert+CV+Fin) ==\n");

    uint8_t tp_blob[256];
    size_t  tp_len = make_sample_tp(tp_blob, sizeof tp_blob);

    quic_conn_t conn;
    uint8_t ch[1024]; size_t ch_len;
    drive_test_setup_conn_with_ch(&conn, tp_blob, tp_len, ch, sizeof ch, &ch_len);

    static const uint8_t srv_priv[32] = {
        1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16,
        17,18,19,20,21,22,23,24, 25,26,27,28,29,30,31,32,
    };
    static const uint8_t srv_random[32] = {
        0xde,0xad,0xbe,0xef, 0xfa,0xce,0xfe,0xed,
        0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
        0xa0,0xa1,0xa2,0xa3, 0xa4,0xa5,0xa6,0xa7,
        0xb0,0xb1,0xb2,0xb3, 0xb4,0xb5,0xb6,0xb7,
    };
    static const uint8_t fake_cert[8] = { 0x30,0x06,0x02,0x01,0x00,0x05,0x00,0x00 };
    static const size_t  cert_lens[1] = { sizeof fake_cert };
    static const uint8_t ed_seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60,
    };

    quic_server_handshake_inputs_t in = {0};
    in.server_priv_x25519 = srv_priv;
    in.server_random      = srv_random;
    in.cert.chain_der     = fake_cert;
    in.cert.cert_lens     = cert_lens;
    in.cert.n_certs       = 1;
    in.cert.ed25519_seed  = ed_seed;

    int rc = quic_server_drive_handshake(&conn, &in);
    check_int("driver returned 0", rc, 0);
    check_int("handshake state populated", conn.have_handshake_state, 1);
    check_int("handshake keys ready",      conn.handshake_keys_ready, 1);
    check_int("Initial blob non-empty",    conn.drv_initial_blob_len > 0, 1);
    check_int("Handshake blob non-empty",  conn.drv_handshake_blob_len > 0, 1);

    /* SH starts with handshake type 0x02. */
    check_int("Initial blob starts with SH (0x02)",
              conn.drv_initial_blob[0], 0x02);
    /* HS blob starts with EE (0x08). */
    check_int("HS blob starts with EE (0x08)",
              conn.drv_handshake_blob[0], 0x08);

    /* Now exercise the emit pipelines end-to-end. */
    uint8_t out[1500];
    size_t  emitted = quic_conn_emit_initial(&conn, out, sizeof out);
    check_int("emit Initial produced bytes", emitted > 0, 1);
    check_int("Initial pn advanced", (long)conn.initial_tx_next_pn, 1);

    emitted = quic_conn_emit_handshake(&conn, out, sizeof out);
    check_int("emit Handshake produced bytes", emitted > 0, 1);
    check_int("Handshake pn advanced", (long)conn.handshake_tx_next_pn, 1);
}

static void test_drive_rejects_no_x25519(void) {
    printf("== drive: rejects CH without X25519 key share ==\n");
    /* Build a CH with no extensions (no x25519). */
    quic_conn_t conn;
    quic_conn_init_server(&conn);
    /* Minimal CH: hs hdr + legacy_version + random + sid=0 + cs + cm + ext_total=0.
     * legacy_version(2) + random(32) + 1 + 2+2 + 1+1 + 2 = 41 bytes body. */
    uint8_t ch[64];
    uint8_t* p = ch;
    *p++ = 0x01; *p++=0; *p++=0; *p++=41;
    *p++ = 0x03; *p++ = 0x03;
    for (int i = 0; i < 32; i++) *p++ = 0;
    *p++ = 0;
    *p++ = 0; *p++ = 2; *p++ = 0x13; *p++ = 0x03;
    *p++ = 1; *p++ = 0;
    *p++ = 0; *p++ = 0;
    if (quic_crypto_rx_stage(&conn.rx_initial, 0, ch, (size_t)(p-ch)) < 0) {
        printf("  FATAL\n"); exit(2);
    }

    static const uint8_t srv_priv[32]   = {1};
    static const uint8_t srv_random[32] = {2};
    static const uint8_t fake_cert[4]   = {0x30,0,0,0};
    static const size_t  cert_lens[1]   = {4};
    static const uint8_t ed_seed[32]    = {3};
    quic_server_handshake_inputs_t in = {0};
    in.server_priv_x25519 = srv_priv;
    in.server_random = srv_random;
    in.cert.chain_der = fake_cert;
    in.cert.cert_lens = cert_lens;
    in.cert.n_certs = 1;
    in.cert.ed25519_seed = ed_seed;

    check_int("driver rejects",
              quic_server_drive_handshake(&conn, &in), -1);
}

static void test_drive_rejects_bad_args(void) {
    printf("== drive: rejects null inputs ==\n");
    quic_conn_t conn; quic_conn_init_server(&conn);
    check_int("null in", quic_server_drive_handshake(&conn, NULL), -1);
    quic_server_handshake_inputs_t in = {0};
    check_int("missing server_priv",
              quic_server_drive_handshake(&conn, &in), -1);
}

/* ---------------- phase 5e7: client Finished + 1-RTT ----------------- */

#include "../tls/keysched.h"

static void test_finish_handshake_round_trip(void) {
    printf("== finish: client Finished verify → 1-RTT keys ==\n");

    /* Drive the full happy-path setup first. */
    uint8_t tp_blob[256];
    size_t  tp_len = make_sample_tp(tp_blob, sizeof tp_blob);

    quic_conn_t conn;
    uint8_t ch[1024]; size_t ch_len;
    drive_test_setup_conn_with_ch(&conn, tp_blob, tp_len, ch, sizeof ch, &ch_len);

    static const uint8_t srv_priv[32] = {
        1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16,
        17,18,19,20,21,22,23,24, 25,26,27,28,29,30,31,32,
    };
    static const uint8_t srv_random[32] = {
        0xde,0xad,0xbe,0xef, 0xfa,0xce,0xfe,0xed,
        0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
        0xa0,0xa1,0xa2,0xa3, 0xa4,0xa5,0xa6,0xa7,
        0xb0,0xb1,0xb2,0xb3, 0xb4,0xb5,0xb6,0xb7,
    };
    static const uint8_t fake_cert[8] = { 0x30,0x06,0x02,0x01,0x00,0x05,0x00,0x00 };
    static const size_t  cert_lens[1] = { sizeof fake_cert };
    static const uint8_t ed_seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60,
    };
    quic_server_handshake_inputs_t in = {0};
    in.server_priv_x25519 = srv_priv;
    in.server_random      = srv_random;
    in.cert.chain_der     = fake_cert;
    in.cert.cert_lens     = cert_lens;
    in.cert.n_certs       = 1;
    in.cert.ed25519_seed  = ed_seed;
    if (quic_server_drive_handshake(&conn, &in) != 0) {
        printf("  FATAL: drive failed\n"); g_fail++; return;
    }

    /* Synthesize the matching client Finished. verify_data is computed
     * against client_handshake_traffic_secret + transcript-thru-server-Fin
     * — which the server has already snapshotted on conn. */
    uint8_t verify_data[32];
    if (tls13_compute_finished(conn.client_handshake_traffic_secret,
                               conn.transcript_hash_thru_server_fin,
                               verify_data) != 0) {
        printf("  FATAL: compute_finished\n"); g_fail++; return;
    }
    uint8_t client_fin[64];
    int fn = tls13_build_finished(client_fin, sizeof client_fin, verify_data);
    if (fn <= 0) { printf("  FATAL: build_finished\n"); g_fail++; return; }

    /* Stage it directly into the conn's Handshake-epoch reassembler. */
    if (quic_crypto_rx_stage(&conn.rx_handshake, 0,
                             client_fin, (size_t)fn) < 0) {
        printf("  FATAL: rx_handshake stage\n"); g_fail++; return;
    }

    int rc = quic_server_finish_handshake(&conn);
    check_int("finish OK",          rc, 0);
    check_int("app keys ready",     conn.app_keys_ready, 1);
    /* app_tx and app_rx must differ. */
    check_int("app tx/rx differ",
              memcmp(conn.app_tx_keys.key,
                     conn.app_rx_keys.key, 16) != 0, 1);
    /* idempotent: second call returns 0 (already-ready short-circuit). */
    check_int("idempotent",         quic_server_finish_handshake(&conn), 0);
}

static void test_finish_rejects_bad_verify(void) {
    printf("== finish: rejects bad verify_data ==\n");
    /* Drive setup. */
    uint8_t tp_blob[256];
    size_t  tp_len = make_sample_tp(tp_blob, sizeof tp_blob);
    quic_conn_t conn;
    uint8_t ch[1024]; size_t ch_len;
    drive_test_setup_conn_with_ch(&conn, tp_blob, tp_len, ch, sizeof ch, &ch_len);
    static const uint8_t srv_priv[32]   = {7};
    static const uint8_t srv_random[32] = {0x33};
    static const uint8_t fake_cert[8]   = {0x30,0x06,0x02,0x01,0x00,0x05,0,0};
    static const size_t  cert_lens[1]   = {sizeof fake_cert};
    static const uint8_t ed_seed[32]    = {0x42};
    quic_server_handshake_inputs_t in = {0};
    in.server_priv_x25519 = srv_priv;
    in.server_random = srv_random;
    in.cert.chain_der = fake_cert;
    in.cert.cert_lens = cert_lens;
    in.cert.n_certs = 1;
    in.cert.ed25519_seed = ed_seed;
    if (quic_server_drive_handshake(&conn, &in) != 0) {
        printf("  FATAL\n"); g_fail++; return;
    }

    /* Forge a Finished with all-zero verify_data. */
    uint8_t bad_fin[36];
    bad_fin[0] = 0x14; bad_fin[1] = 0; bad_fin[2] = 0; bad_fin[3] = 32;
    memset(bad_fin + 4, 0, 32);
    if (quic_crypto_rx_stage(&conn.rx_handshake, 0,
                             bad_fin, sizeof bad_fin) < 0) {
        printf("  FATAL\n"); g_fail++; return;
    }
    check_int("verify rejected", quic_server_finish_handshake(&conn), -1);
    check_int("app keys NOT ready", conn.app_keys_ready, 0);
}

static void test_finish_rejects_no_state(void) {
    printf("== finish: rejects without driver run ==\n");
    quic_conn_t conn; quic_conn_init_server(&conn);
    check_int("no state → -1", quic_server_finish_handshake(&conn), -1);
}

static void test_finish_rejects_short_buffer(void) {
    printf("== finish: rejects truncated Finished ==\n");
    uint8_t tp_blob[256];
    size_t  tp_len = make_sample_tp(tp_blob, sizeof tp_blob);
    quic_conn_t conn;
    uint8_t ch[1024]; size_t ch_len;
    drive_test_setup_conn_with_ch(&conn, tp_blob, tp_len, ch, sizeof ch, &ch_len);
    static const uint8_t p[32] = {1};
    static const uint8_t r[32] = {2};
    static const uint8_t cd[8] = {0x30,0x06,0x02,0x01,0x00,0x05,0,0};
    static const size_t  cl[1] = {8};
    static const uint8_t s[32] = {3};
    quic_server_handshake_inputs_t in = {
        .server_priv_x25519 = p, .server_random = r,
        .cert = { .chain_der = cd, .cert_lens = cl, .n_certs = 1, .ed25519_seed = s }
    };
    if (quic_server_drive_handshake(&conn, &in) != 0) {
        printf("  FATAL\n"); g_fail++; return;
    }
    /* Stage only the 4-byte header — body absent. */
    static const uint8_t hdr[4] = { 0x14, 0, 0, 32 };
    quic_crypto_rx_stage(&conn.rx_handshake, 0, hdr, sizeof hdr);
    check_int("short body → -1", quic_server_finish_handshake(&conn), -1);
}

/* ---------------- phase 6a: 1-RTT short-header tests ---------------- */

static void make_app_keys_pair(quic_short_keys_t* tx, quic_short_keys_t* rx)
{
    static const uint8_t s[32] = {
        0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80,
        0x90,0xa0,0xb0,0xc0, 0xd0,0xe0,0xf0,0x00,
        0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc, 0xdd,0xee,0xff,0x01,
    };
    static const uint8_t c[32] = {
        0xaa,0xbb,0xcc,0xdd, 0xee,0xff,0x00,0x11,
        0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,
        0xa0,0xb0,0xc0,0xd0, 0xe0,0xf0,0x01,0x02,
        0x03,0x04,0x05,0x06, 0x07,0x08,0x09,0x0a,
    };
    quic_keys_t big;
    if (!quic_keys_from_secret(s, 32, 16, 16, &big)) {
        printf("  FATAL keys s\n"); exit(2);
    }
    memcpy(tx->key, big.key, 16); memcpy(tx->iv, big.iv, 12); memcpy(tx->hp, big.hp, 16);
    if (!quic_keys_from_secret(c, 32, 16, 16, &big)) {
        printf("  FATAL keys c\n"); exit(2);
    }
    memcpy(rx->key, big.key, 16); memcpy(rx->iv, big.iv, 12); memcpy(rx->hp, big.hp, 16);
}

static void test_short_pkt_round_trip(void) {
    printf("== short: build → parse round-trip ==\n");
    quic_short_keys_t tx, rx;
    make_app_keys_pair(&tx, &rx);
    /* Symmetric: server's tx = client's rx. We reuse `tx` for both sides. */
    static const uint8_t dcid[] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8};
    quic_short_pkt_t pkt = {0};
    memcpy(pkt.dcid, dcid, sizeof dcid);
    pkt.dcid_len = sizeof dcid;
    pkt.pn = 42;
    pkt.pn_len = 2;
    static const uint8_t pl[] = {0xde,0xad,0xbe,0xef,0xfa,0xce};
    pkt.payload = pl; pkt.payload_len = sizeof pl;

    uint8_t wire[256];
    size_t n = quic_short_build(wire, sizeof wire, &pkt, &tx);
    check_int("build produced bytes", n > 0, 1);
    /* form bit=0, fixed=1 in plaintext byte0. After HP applied, those
     * top two bits remain (only low 5 bits are protected). */
    check_int("byte0 form=0", (wire[0] & 0x80) == 0 ? 0 : 1, 0);
    check_int("byte0 fixed=1", (wire[0] & 0x40) ? 0 : 1, 0);

    quic_short_pkt_t got;
    uint8_t scratch[256];
    int rc = quic_short_parse(wire, n, sizeof dcid, &tx,
                              &got, scratch, sizeof scratch);
    check_int("parse OK", rc, 0);
    check_int("pn round-tripped", (long)got.pn, 42);
    check_int("pn_len round-tripped", (int)got.pn_len, 2);
    check_int("payload len match", (long)got.payload_len, (long)sizeof pl);
    check_int("payload bytes match", memcmp(got.payload, pl, sizeof pl), 0);
    check_int("dcid match", memcmp(got.dcid, dcid, sizeof dcid), 0);
    (void)rx;
}

static void test_short_pkt_rejects_long_form(void) {
    printf("== short: rejects long-header byte0 ==\n");
    quic_short_keys_t tx, rx; make_app_keys_pair(&tx, &rx);
    uint8_t fake[64]; memset(fake, 0, sizeof fake);
    fake[0] = 0xc0; /* long-bit=1 */
    quic_short_pkt_t got; uint8_t scratch[64];
    check_int("long-form rejected",
              quic_short_parse(fake, sizeof fake, 8, &tx, &got, scratch, sizeof scratch),
              -1);
}

static void test_short_pkt_rejects_clear_fixed(void) {
    printf("== short: rejects cleared fixed bit ==\n");
    quic_short_keys_t tx, rx; make_app_keys_pair(&tx, &rx);
    uint8_t fake[64]; memset(fake, 0, sizeof fake);
    fake[0] = 0x00; /* form=0, fixed=0 */
    quic_short_pkt_t got; uint8_t scratch[64];
    check_int("clear-fixed rejected",
              quic_short_parse(fake, sizeof fake, 8, &tx, &got, scratch, sizeof scratch),
              -1);
}

static void test_short_pkt_aead_failure(void) {
    printf("== short: AEAD failure rejected ==\n");
    quic_short_keys_t tx, rx; make_app_keys_pair(&tx, &rx);
    static const uint8_t dcid[] = {1,2,3,4,5,6,7,8};
    quic_short_pkt_t pkt = {0};
    memcpy(pkt.dcid, dcid, sizeof dcid);
    pkt.dcid_len = sizeof dcid; pkt.pn = 1; pkt.pn_len = 1;
    static const uint8_t pl[16] = {0xff,0x55,0x00,0x11,0x22,0x33,0x44,0x55,
                                   0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd};
    pkt.payload = pl; pkt.payload_len = sizeof pl;
    uint8_t wire[128];
    size_t n = quic_short_build(wire, sizeof wire, &pkt, &tx);
    if (n == 0) { printf("  FATAL\n"); g_fail++; return; }
    /* Flip a tag byte. */
    wire[n - 1] ^= 0x01;
    quic_short_pkt_t got; uint8_t scratch[128];
    check_int("AEAD reject", quic_short_parse(wire, n, sizeof dcid, &tx,
                                              &got, scratch, sizeof scratch), -1);
}

static void test_conn_emit_recv_app_round_trip(void) {
    printf("== conn: emit + recv 1-RTT round-trip ==\n");

    /* Drive a full handshake on the server, then symmetric reverse on a
     * second conn so we can use server.app_tx_keys as client.app_rx_keys. */
    uint8_t tp_blob[256];
    size_t  tp_len = make_sample_tp(tp_blob, sizeof tp_blob);
    quic_conn_t server, client;
    uint8_t ch[1024]; size_t ch_len;
    drive_test_setup_conn_with_ch(&server, tp_blob, tp_len, ch, sizeof ch, &ch_len);

    static const uint8_t srv_priv[32] = {1,2,3,4};
    static const uint8_t srv_random[32] = {5,6,7,8};
    static const uint8_t fake_cert[8] = {0x30,0x06,0x02,0x01,0x00,0x05,0,0};
    static const size_t  cert_lens[1] = {8};
    static const uint8_t ed_seed[32] = {9,10,11,12};
    quic_server_handshake_inputs_t in = {
        .server_priv_x25519 = srv_priv, .server_random = srv_random,
        .cert = { .chain_der = fake_cert, .cert_lens = cert_lens, .n_certs = 1, .ed25519_seed = ed_seed }
    };
    if (quic_server_drive_handshake(&server, &in) != 0) {
        printf("  FATAL drive\n"); g_fail++; return;
    }
    /* Stage client Finished. */
    uint8_t vd[32];
    if (tls13_compute_finished(server.client_handshake_traffic_secret,
                               server.transcript_hash_thru_server_fin, vd) != 0) {
        printf("  FATAL fin\n"); g_fail++; return;
    }
    uint8_t cf[64]; int fn = tls13_build_finished(cf, sizeof cf, vd);
    if (fn <= 0) { printf("  FATAL build_fin\n"); g_fail++; return; }
    quic_crypto_rx_stage(&server.rx_handshake, 0, cf, (size_t)fn);
    if (quic_server_finish_handshake(&server) != 0) {
        printf("  FATAL finish\n"); g_fail++; return;
    }

    /* Build a peer (client) view. Mirror everything: peer_scid<->our_scid,
     * app_tx<->app_rx. Easiest: reuse another conn struct and copy
     * keys+CIDs from server with directions swapped. */
    quic_conn_init_server(&client);
    memcpy(client.our_scid, server.peer_scid, server.peer_scid_len);
    client.our_scid_len = server.peer_scid_len;
    memcpy(client.peer_scid, server.our_scid, server.our_scid_len);
    client.peer_scid_len = server.our_scid_len;
    client.peer_addrs_known = 1;
    client.app_tx_keys = server.app_rx_keys;
    client.app_rx_keys = server.app_tx_keys;
    client.app_keys_ready = 1;

    /* Server emits an app packet with a STREAM frame payload. */
    static const uint8_t pl[] = { 0x01, 0x01, 0x01 };  /* three PING frames */
    uint8_t out[1500];
    size_t n = quic_conn_emit_app(&server, pl, sizeof pl, out, sizeof out);
    check_int("emit produced bytes", n > 0, 1);
    check_int("server app pn advanced", (long)server.app_tx_next_pn, 1);

    int rc = quic_conn_recv_app(&client, out, n);
    check_int("client recv OK", rc, 0);
    check_int("client app pkts++", (long)client.app_pkts_rcvd, 1);
}

static void test_conn_emit_app_no_keys(void) {
    printf("== conn: emit_app rejects without keys ==\n");
    quic_conn_t c; quic_conn_init_server(&c);
    uint8_t out[256];
    static const uint8_t pl[8] = {0};
    check_int("no keys → 0",
              (long)quic_conn_emit_app(&c, pl, sizeof pl, out, sizeof out), 0);
}

static void test_conn_recv_app_no_keys(void) {
    printf("== conn: recv_app rejects without keys ==\n");
    quic_conn_t c; quic_conn_init_server(&c);
    uint8_t fake[64]; memset(fake, 0, sizeof fake); fake[0] = 0x40;
    check_int("no keys → -1", quic_conn_recv_app(&c, fake, sizeof fake), -1);
}

/* ============================================================== */
/*                       phase 6b STREAM tests                      */
/* ============================================================== */

static void test_stream_in_order(void) {
    printf("== stream: in-order ingest ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 4);
    static const uint8_t a[] = "hello ";
    static const uint8_t b[] = "world!";
    check_int("ingest a", quic_stream_rx_ingest(&s, 0, a, 6, 0), 1);
    check_int("ingest b+FIN", quic_stream_rx_ingest(&s, 6, b, 6, 1), 1);
    size_t n; const uint8_t* p = quic_stream_rx_peek(&s, &n);
    check_int("peek len", (long)n, 12);
    check_int("byte0 'h'", p[0], 'h');
    check_int("byte11 '!'", p[11], '!');
    check_int("complete", quic_stream_rx_is_complete(&s), 1);
}

static void test_stream_out_of_order(void) {
    printf("== stream: out-of-order with gap fill ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 7);
    static const uint8_t mid[] = "mid";
    static const uint8_t hd[]  = "hd";
    static const uint8_t tl[]  = "tail";
    check_int("ingest mid@2", quic_stream_rx_ingest(&s, 2, mid, 3, 0), 1);
    /* nothing in-order yet */
    size_t n; (void)quic_stream_rx_peek(&s, &n);
    check_int("no contig yet", (long)n, 0);
    check_int("ingest hd@0",  quic_stream_rx_ingest(&s, 0, hd, 2, 0), 1);
    (void)quic_stream_rx_peek(&s, &n);
    check_int("now 5 contig", (long)n, 5);
    check_int("ingest tl@5+FIN", quic_stream_rx_ingest(&s, 5, tl, 4, 1), 1);
    check_int("complete", quic_stream_rx_is_complete(&s), 1);
}

static void test_stream_duplicate(void) {
    printf("== stream: duplicate returns 0 ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 9);
    static const uint8_t d[] = "abcd";
    check_int("first",  quic_stream_rx_ingest(&s, 0, d, 4, 0), 1);
    check_int("dup",    quic_stream_rx_ingest(&s, 0, d, 4, 0), 0);
}

static void test_stream_fin_size_change(void) {
    printf("== stream: FIN size change → -1 ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 11);
    static const uint8_t d[] = "abcdef";
    check_int("data+FIN@6", quic_stream_rx_ingest(&s, 0, d, 6, 1), 1);
    /* re-FIN at different size */
    check_int("re-FIN@4 → -1",
              quic_stream_rx_ingest(&s, 0, d, 4, 1), -1);
}

static void test_stream_data_past_fin(void) {
    printf("== stream: data past final_size → -1 ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 13);
    static const uint8_t d[] = "abcd";
    check_int("data+FIN@4", quic_stream_rx_ingest(&s, 0, d, 4, 1), 1);
    check_int("extend@4 → -1",
              quic_stream_rx_ingest(&s, 4, d, 4, 0), -1);
}

static void test_stream_fin_smaller_than_staged(void) {
    printf("== stream: FIN smaller than already staged → -1 ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 15);
    static const uint8_t d[] = "abcdef";
    check_int("stage hi@10", quic_stream_rx_ingest(&s, 10, d, 6, 0), 1);
    /* highest = 16; declare FIN with smaller size */
    static const uint8_t e[] = "x";
    check_int("FIN@1 → -1", quic_stream_rx_ingest(&s, 0, e, 1, 1), -1);
}

static void test_stream_overflow_capacity(void) {
    printf("== stream: capacity overflow → -1 ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 17);
    static uint8_t big[16]; memset(big, 'q', sizeof big);
    /* offset just past cap → should fail */
    check_int("overflow → -1",
              quic_stream_rx_ingest(&s, QUIC_STREAM_RX_CAP + 1, big, 8, 0),
              -1);
}

static void test_stream_empty_fin(void) {
    printf("== stream: empty STREAM frame with FIN ==\n");
    quic_stream_rx_t s; quic_stream_rx_init(&s, 19);
    static const uint8_t d[] = "abc";
    check_int("data@0", quic_stream_rx_ingest(&s, 0, d, 3, 0), 1);
    check_int("empty FIN@3", quic_stream_rx_ingest(&s, 3, NULL, 0, 1), 1);
    check_int("complete", quic_stream_rx_is_complete(&s), 1);
}

/* ---- conn-level dispatch: 1-RTT recv routes STREAM into per-stream slot ---- */

static void test_conn_recv_app_dispatches_stream(void) {
    printf("== conn: 1-RTT STREAM dispatched into per-stream rx ==\n");
    /* Simpler than full handshake: synthesise matching app keys + CIDs
     * directly on two conns. */
    quic_conn_t server, client;
    quic_conn_init_server(&server);
    quic_conn_init_server(&client);
    static const uint8_t scid_a[] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8};
    static const uint8_t scid_b[] = {0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8};
    quic_conn_set_our_scid(&server, scid_a, sizeof scid_a);
    quic_conn_set_our_scid(&client, scid_b, sizeof scid_b);
    memcpy(server.peer_scid, scid_b, sizeof scid_b); server.peer_scid_len = 8;
    memcpy(client.peer_scid, scid_a, sizeof scid_a); client.peer_scid_len = 8;
    server.peer_addrs_known = client.peer_addrs_known = 1;
    /* Symmetric keys (one direction is enough for this test). */
    quic_handshake_keys_t k;
    memset(&k, 0, sizeof k);
    for (int i = 0; i < 16; i++) k.key[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 12; i++) k.iv[i]  = (uint8_t)(0x20 + i);
    for (int i = 0; i < 16; i++) k.hp[i]  = (uint8_t)(0x30 + i);
    client.app_tx_keys = k; server.app_rx_keys = k;
    client.app_keys_ready = server.app_keys_ready = 1;

    /* Build a STREAM frame on the client side and ship it to server. */
    uint8_t frames[64];
    static const uint8_t body[] = "GET /";
    size_t fn = quic_frame_stream_encode(frames, sizeof frames,
                                         /*stream_id*/ 0,
                                         /*offset*/ 0,
                                         body, sizeof body - 1,
                                         /*fin*/ 1);
    check_int("frame encoded", fn > 0, 1);

    uint8_t out[1500];
    size_t pn = quic_conn_emit_app(&client, frames, fn, out, sizeof out);
    check_int("emit OK", pn > 0, 1);
    int rc = quic_conn_recv_app(&server, out, pn);
    check_int("server recv OK", rc, 0);

    /* Server should now have stream 0 reassembled. */
    int found = -1;
    for (unsigned i = 0; i < QUIC_CONN_MAX_STREAMS; i++)
        if (server.streams[i].in_use && server.streams[i].stream_id == 0) {
            found = (int)i; break;
        }
    check_int("stream slot claimed", found >= 0, 1);
    check_int("stream complete", quic_stream_rx_is_complete(&server.streams[found]), 1);
    size_t n; const uint8_t* p = quic_stream_rx_peek(&server.streams[found], &n);
    check_int("5 bytes", (long)n, 5);
    check_int("starts with 'G'", p[0], 'G');
}

static void test_conn_recv_app_rejects_new_token(void) {
    printf("== conn: 1-RTT NEW_TOKEN from peer → -1 ==\n");
    quic_conn_t server, client;
    quic_conn_init_server(&server);
    quic_conn_init_server(&client);
    static const uint8_t scid_a[] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8};
    static const uint8_t scid_b[] = {0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8};
    quic_conn_set_our_scid(&server, scid_a, sizeof scid_a);
    quic_conn_set_our_scid(&client, scid_b, sizeof scid_b);
    memcpy(server.peer_scid, scid_b, 8); server.peer_scid_len = 8;
    memcpy(client.peer_scid, scid_a, 8); client.peer_scid_len = 8;
    server.peer_addrs_known = client.peer_addrs_known = 1;
    quic_handshake_keys_t k; memset(&k, 0, sizeof k);
    for (int i = 0; i < 16; i++) { k.key[i] = (uint8_t)(0x40+i); k.hp[i] = (uint8_t)(0x50+i); }
    for (int i = 0; i < 12; i++) k.iv[i] = (uint8_t)(0x60+i);
    client.app_tx_keys = k; server.app_rx_keys = k;
    client.app_keys_ready = server.app_keys_ready = 1;

    uint8_t frames[16];
    frames[0] = 0x07;
    frames[1] = 0x04;
    frames[2] = 'a'; frames[3] = 'b'; frames[4] = 'c'; frames[5] = 'd';

    uint8_t out[1500];
    size_t pn = quic_conn_emit_app(&client, frames, 6, out, sizeof out);
    check_int("emit OK", pn > 0, 1);
    int rc = quic_conn_recv_app(&server, out, pn);
    check_int("rejected", rc, -1);
}

static void test_conn_recv_app_rejects_handshake_done(void) {
    printf("== conn: 1-RTT HANDSHAKE_DONE from peer → -1 ==\n");
    quic_conn_t server, client;
    quic_conn_init_server(&server);
    quic_conn_init_server(&client);
    static const uint8_t scid_a[] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8};
    static const uint8_t scid_b[] = {0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8};
    quic_conn_set_our_scid(&server, scid_a, sizeof scid_a);
    quic_conn_set_our_scid(&client, scid_b, sizeof scid_b);
    memcpy(server.peer_scid, scid_b, 8); server.peer_scid_len = 8;
    memcpy(client.peer_scid, scid_a, 8); client.peer_scid_len = 8;
    server.peer_addrs_known = client.peer_addrs_known = 1;
    quic_handshake_keys_t k; memset(&k, 0, sizeof k);
    for (int i = 0; i < 16; i++) { k.key[i] = (uint8_t)(0x70+i); k.hp[i] = (uint8_t)(0x80+i); }
    for (int i = 0; i < 12; i++) k.iv[i] = (uint8_t)(0x90+i);
    client.app_tx_keys = k; server.app_rx_keys = k;
    client.app_keys_ready = server.app_keys_ready = 1;

    uint8_t frames[16] = { 0x1e };
    /* pad with PADDING so build's HP-sample requirement is met */
    uint8_t out[1500];
    size_t pn = quic_conn_emit_app(&client, frames, sizeof frames, out, sizeof out);
    check_int("emit OK", pn > 0, 1);
    int rc = quic_conn_recv_app(&server, out, pn);
    check_int("rejected", rc, -1);
}

static void test_conn_recv_app_stream_overflow_slots(void) {
    printf("== conn: too many distinct streams → -1 ==\n");
    quic_conn_t server, client;
    quic_conn_init_server(&server);
    quic_conn_init_server(&client);
    static const uint8_t scid_a[] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8};
    static const uint8_t scid_b[] = {0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8};
    quic_conn_set_our_scid(&server, scid_a, sizeof scid_a);
    quic_conn_set_our_scid(&client, scid_b, sizeof scid_b);
    memcpy(server.peer_scid, scid_b, 8); server.peer_scid_len = 8;
    memcpy(client.peer_scid, scid_a, 8); client.peer_scid_len = 8;
    server.peer_addrs_known = client.peer_addrs_known = 1;
    quic_handshake_keys_t k; memset(&k, 0, sizeof k);
    for (int i = 0; i < 16; i++) { k.key[i] = (uint8_t)(0xa0+i); k.hp[i] = (uint8_t)(0xb0+i); }
    for (int i = 0; i < 12; i++) k.iv[i] = (uint8_t)(0xc0+i);
    client.app_tx_keys = k; server.app_rx_keys = k;
    client.app_keys_ready = server.app_keys_ready = 1;

    for (unsigned i = 0; i <= QUIC_CONN_MAX_STREAMS; i++) {
        uint8_t frames[32];
        static const uint8_t body[] = "x";
        size_t fn = quic_frame_stream_encode(frames, sizeof frames,
                                             /*stream_id*/ i * 4u,
                                             0, body, 1, 0);
        uint8_t out[1500];
        size_t pn = quic_conn_emit_app(&client, frames, fn, out, sizeof out);
        int rc = quic_conn_recv_app(&server, out, pn);
        if (i < QUIC_CONN_MAX_STREAMS) {
            if (rc != 0) { printf("  FAIL slot %u rc=%d\n", i, rc); g_fail++; return; }
        } else {
            check_int("overflow rejected", rc, -1);
        }
    }
}

/* ============================================================== */
/*                    phase 6c HTTP/3 frame tests                  */
/* ============================================================== */

static void test_h3_classify(void) {
    printf("== h3: classify_type ==\n");
    check_int("DATA",         h3_classify_type(0x00), H3_FT_DATA);
    check_int("HEADERS",      h3_classify_type(0x01), H3_FT_HEADERS);
    check_int("CANCEL_PUSH",  h3_classify_type(0x03), H3_FT_CANCEL_PUSH);
    check_int("SETTINGS",     h3_classify_type(0x04), H3_FT_SETTINGS);
    check_int("PUSH_PROMISE", h3_classify_type(0x05), H3_FT_PUSH_PROMISE);
    check_int("GOAWAY",       h3_classify_type(0x07), H3_FT_GOAWAY);
    check_int("MAX_PUSH_ID",  h3_classify_type(0x0d), H3_FT_MAX_PUSH_ID);
    check_int("h2 PRIORITY=RESERVED",     h3_classify_type(0x02), H3_FT_RESERVED);
    check_int("h2 PING=RESERVED",         h3_classify_type(0x06), H3_FT_RESERVED);
    check_int("h2 WINDOW_UPDATE=RESERVED",h3_classify_type(0x08), H3_FT_RESERVED);
    check_int("h2 CONTINUATION=RESERVED", h3_classify_type(0x09), H3_FT_RESERVED);
    check_int("grease=UNKNOWN",   h3_classify_type(0x21), H3_FT_UNKNOWN);
}

static void test_h3_encode_decode_data(void) {
    printf("== h3: DATA encode + decode round-trip ==\n");
    uint8_t out[64];
    static const uint8_t pl[] = "hello h3";
    size_t n = h3_frame_encode(out, sizeof out, H3_FT_DATA, pl, sizeof pl - 1);
    check_int("encoded", n > 0, 1);
    /* type=0x00 (1 byte varint), length=8 (1 byte varint), payload 8 = 10 */
    check_int("size = 10", (long)n, 10);
    h3_frame_t f;
    size_t consumed = h3_frame_decode(out, n, &f);
    check_int("consumed", (long)consumed, (long)n);
    check_int("type DATA", f.type, H3_FT_DATA);
    check_int("len 8", (long)f.length, 8);
    check_int("payload[0] 'h'", f.payload[0], 'h');
}

static void test_h3_decode_partial(void) {
    printf("== h3: decode returns NEED_MORE on partial input ==\n");
    /* Encode HEADERS with 4-byte payload, then truncate. */
    uint8_t out[16];
    static const uint8_t pl[] = "abcd";
    size_t n = h3_frame_encode(out, sizeof out, H3_FT_HEADERS, pl, 4);
    h3_frame_t f;
    /* Truncate at every prefix shorter than n. */
    for (size_t k = 0; k < n; k++) {
        size_t r = h3_frame_decode(out, k, &f);
        check_int("need more", r == H3_DECODE_NEED_MORE, 1);
    }
    check_int("full decodes", h3_frame_decode(out, n, &f) == n, 1);
}

static void test_h3_decode_grease(void) {
    printf("== h3: grease type classified as UNKNOWN ==\n");
    /* Type 0x21 = 33; length 0; payload empty. */
    uint8_t out[8];
    size_t n = h3_frame_encode(out, sizeof out, 0x21, NULL, 0);
    h3_frame_t f;
    check_int("decoded", h3_frame_decode(out, n, &f) == n, 1);
    check_int("type UNKNOWN", f.type, H3_FT_UNKNOWN);
    check_int("raw 0x21", (long)f.raw_type, 0x21);
    check_int("len 0", (long)f.length, 0);
}

static void test_h3_decode_reserved(void) {
    printf("== h3: h2-reserved type classified as RESERVED ==\n");
    uint8_t out[8];
    size_t n = h3_frame_encode(out, sizeof out, 0x06 /* h2 PING */, NULL, 0);
    h3_frame_t f;
    check_int("decoded", h3_frame_decode(out, n, &f) == n, 1);
    check_int("type RESERVED", f.type, H3_FT_RESERVED);
}

static void test_h3_settings_round_trip(void) {
    printf("== h3: SETTINGS payload build + iterate ==\n");
    uint8_t pl[64]; size_t plen = 0;
    plen = h3_settings_append(pl, sizeof pl, plen,
                              H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0);
    check_int("append 1", plen > 0, 1);
    plen = h3_settings_append(pl, sizeof pl, plen,
                              H3_SETTINGS_MAX_FIELD_SECTION_SIZE, 16384);
    check_int("append 2", plen > 0, 1);
    plen = h3_settings_append(pl, sizeof pl, plen,
                              H3_SETTINGS_QPACK_BLOCKED_STREAMS, 0);
    check_int("append 3", plen > 0, 1);

    /* Iterate. */
    size_t cur = 0;
    uint64_t id, val;
    int r;
    r = h3_settings_next(pl, plen, &cur, &id, &val);
    check_int("pair1 ok", r, 1);
    check_int("pair1 id",  (long)id, H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    check_int("pair1 val", (long)val, 0);
    r = h3_settings_next(pl, plen, &cur, &id, &val);
    check_int("pair2 ok", r, 1);
    check_int("pair2 id",  (long)id, H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
    check_int("pair2 val", (long)val, 16384);
    r = h3_settings_next(pl, plen, &cur, &id, &val);
    check_int("pair3 ok", r, 1);
    check_int("pair3 id",  (long)id, H3_SETTINGS_QPACK_BLOCKED_STREAMS);
    r = h3_settings_next(pl, plen, &cur, &id, &val);
    check_int("end", r, 0);
}

static void test_h3_settings_truncated(void) {
    printf("== h3: SETTINGS with trailing identifier-without-value → -1 ==\n");
    uint8_t pl[8]; size_t plen = 0;
    plen = h3_settings_append(pl, sizeof pl, plen, 0x01, 100);
    check_int("seed", plen > 0, 1);
    /* Append a stray identifier byte (1-byte varint 0x05) with no value. */
    pl[plen++] = 0x05;
    size_t cur = 0;
    uint64_t id, val;
    int r = h3_settings_next(pl, plen, &cur, &id, &val);
    check_int("first ok", r, 1);
    r = h3_settings_next(pl, plen, &cur, &id, &val);
    check_int("trailing → -1", r, -1);
}

static void test_h3_encode_overflow(void) {
    printf("== h3: encode rejects too-small buffer ==\n");
    uint8_t out[3];
    static const uint8_t pl[8] = {0};
    check_int("overflow → 0",
              (long)h3_frame_encode(out, sizeof out, H3_FT_DATA, pl, sizeof pl), 0);
}

/* ============================================================== */
/*                  phase 6d1 QPACK static tests                   */
/* ============================================================== */

static void test_qpack_static_lookup(void) {
    printf("== qpack: static table spot checks ==\n");
    const char* nm; const char* val; size_t nl, vl;
    check_int("idx 0  (:authority)", qpack_static_get(0,  &nm, &nl, &val, &vl), 0);
    check_int(":authority", strcmp(nm, ":authority") == 0, 1);
    check_int("idx 17 (:method GET)", qpack_static_get(17, &nm, &nl, &val, &vl), 0);
    check_int("name :method", strcmp(nm, ":method") == 0, 1);
    check_int("val GET",     strcmp(val, "GET") == 0, 1);
    check_int("idx 25 (:status 200)", qpack_static_get(25, &nm, &nl, &val, &vl), 0);
    check_int("val 200",     strcmp(val, "200") == 0, 1);
    check_int("idx 98 (x-frame sameorigin)", qpack_static_get(98, &nm, &nl, &val, &vl), 0);
    check_int("idx 99 OOR", qpack_static_get(99, &nm, &nl, &val, &vl), -1);
}

static void test_qpack_decode_indexed(void) {
    printf("== qpack: decode three indexed lines ==\n");
    /* :method GET, :scheme https, :status 200 */
    uint8_t buf[16]; size_t off = 0;
    off += qpack_encode_prefix_empty(buf + off, sizeof buf - off);
    off += qpack_encode_indexed_static(buf + off, sizeof buf - off, 17);
    off += qpack_encode_indexed_static(buf + off, sizeof buf - off, 23);
    off += qpack_encode_indexed_static(buf + off, sizeof buf - off, 25);
    qpack_field_t fields[8]; size_t nf = 8;
    qpack_status_t st = qpack_decode_field_section(buf, off, fields, &nf);
    check_int("OK", st, QPACK_OK);
    check_int("3 fields", (long)nf, 3);
    check_int("name :method", memcmp(fields[0].name, ":method", 7) == 0, 1);
    check_int("val GET",     memcmp(fields[0].value, "GET", 3) == 0, 1);
    check_int("name :scheme", memcmp(fields[1].name, ":scheme", 7) == 0, 1);
    check_int("val https",   memcmp(fields[1].value, "https", 5) == 0, 1);
    check_int("val 200",     memcmp(fields[2].value, "200", 3) == 0, 1);
}

static void test_qpack_decode_literal_with_static_name(void) {
    printf("== qpack: decode literal-with-static-name ==\n");
    uint8_t buf[64]; size_t off = 0;
    off += qpack_encode_prefix_empty(buf + off, sizeof buf - off);
    /* :authority = "wavefunctionlabs.com" — name idx 0 */
    static const uint8_t v[] = "wavefunctionlabs.com";
    off += qpack_encode_literal_static_name(buf + off, sizeof buf - off,
                                            0, v, sizeof v - 1);
    qpack_field_t fields[4]; size_t nf = 4;
    qpack_status_t st = qpack_decode_field_section(buf, off, fields, &nf);
    check_int("OK", st, QPACK_OK);
    check_int("1 field", (long)nf, 1);
    check_int("name :authority", memcmp(fields[0].name, ":authority", 10) == 0, 1);
    check_int("value matches", fields[0].value_len == sizeof v - 1, 1);
    check_int("val first byte 'w'", fields[0].value[0], 'w');
}

static void test_qpack_decode_literal_with_literal_name(void) {
    printf("== qpack: decode literal-with-literal-name ==\n");
    uint8_t buf[64]; size_t off = 0;
    off += qpack_encode_prefix_empty(buf + off, sizeof buf - off);
    static const uint8_t nm[]  = "x-custom";
    static const uint8_t val[] = "yes";
    off += qpack_encode_literal(buf + off, sizeof buf - off,
                                nm, sizeof nm - 1, val, sizeof val - 1);
    qpack_field_t fields[4]; size_t nf = 4;
    qpack_status_t st = qpack_decode_field_section(buf, off, fields, &nf);
    check_int("OK", st, QPACK_OK);
    check_int("1 field", (long)nf, 1);
    check_int("name x-custom", memcmp(fields[0].name, "x-custom", 8) == 0, 1);
    check_int("val yes", memcmp(fields[0].value, "yes", 3) == 0, 1);
}

static void test_qpack_decode_rejects_huffman(void) {
    printf("== qpack: H bit on value rejected with QPACK_ERR_HUFFMAN ==\n");
    uint8_t buf[16];
    buf[0] = 0; buf[1] = 0;     /* prefix */
    buf[2] = 0x70;              /* literal-w/ static-name, idx 0 */
    buf[3] = 0x83;              /* H=1, len=3 */
    buf[4] = 0xab; buf[5] = 0xcd; buf[6] = 0xef;
    qpack_field_t fields[4]; size_t nf = 4;
    qpack_status_t st = qpack_decode_field_section(buf, 7, fields, &nf);
    check_int("ERR_HUFFMAN", st, QPACK_ERR_HUFFMAN);
}

static void test_qpack_decode_rejects_dynamic(void) {
    printf("== qpack: dynamic-table reference rejected ==\n");
    /* RIC=0, delta=0; then T=0 indexed line (dyn). 0x80 alone with low bits is dyn idx. */
    uint8_t buf[8] = {0, 0, 0x80};   /* indexed line, T=0, idx=0 in dyn table */
    qpack_field_t fields[4]; size_t nf = 4;
    qpack_status_t st = qpack_decode_field_section(buf, 3, fields, &nf);
    check_int("ERR_DYNAMIC_REQ", st, QPACK_ERR_DYNAMIC_REQ);
}

static void test_qpack_decode_rejects_nonzero_ric(void) {
    printf("== qpack: non-zero Required Insert Count rejected ==\n");
    uint8_t buf[4] = { 1, 0, 0xc0 };  /* RIC=1, delta=0, then idx 0 */
    qpack_field_t fields[4]; size_t nf = 4;
    qpack_status_t st = qpack_decode_field_section(buf, 3, fields, &nf);
    check_int("ERR_DYNAMIC_REQ", st, QPACK_ERR_DYNAMIC_REQ);
}

static void test_qpack_decode_truncated(void) {
    printf("== qpack: truncated value bytes → ERR_TRUNCATED ==\n");
    uint8_t buf[16];
    buf[0] = 0; buf[1] = 0;
    buf[2] = 0x70;            /* literal w/static-name idx 0 */
    buf[3] = 0x05;            /* value-len = 5, no H */
    buf[4] = 'a'; buf[5] = 'b'; /* only 2 bytes follow */
    qpack_field_t fields[4]; size_t nf = 4;
    qpack_status_t st = qpack_decode_field_section(buf, 6, fields, &nf);
    check_int("ERR_TRUNCATED", st, QPACK_ERR_TRUNCATED);
}

static void test_qpack_encode_oor_index(void) {
    printf("== qpack: encode rejects out-of-range static index ==\n");
    uint8_t out[8];
    check_int("idx 99 → 0",
              (long)qpack_encode_indexed_static(out, sizeof out, 99), 0);
    check_int("idx 999 → 0",
              (long)qpack_encode_indexed_static(out, sizeof out, 999), 0);
}

static void test_qpack_realistic_response(void) {
    printf("== qpack: realistic 200-OK response section round-trip ==\n");
    uint8_t buf[128]; size_t off = 0;
    off += qpack_encode_prefix_empty(buf + off, sizeof buf - off);
    off += qpack_encode_indexed_static(buf + off, sizeof buf - off, 25);  /* :status 200 */
    static const uint8_t srv[] = "picoweb";
    off += qpack_encode_literal_static_name(buf + off, sizeof buf - off,
                                            92 /* server */, srv, sizeof srv - 1);
    off += qpack_encode_indexed_static(buf + off, sizeof buf - off, 52);  /* content-type text/html;charset=utf-8 */
    qpack_field_t fields[8]; size_t nf = 8;
    qpack_status_t st = qpack_decode_field_section(buf, off, fields, &nf);
    check_int("OK", st, QPACK_OK);
    check_int("3 fields", (long)nf, 3);
    check_int(":status 200", memcmp(fields[0].value, "200", 3) == 0, 1);
    check_int("server picoweb",
              fields[1].value_len == 7 &&
              memcmp(fields[1].value, "picoweb", 7) == 0, 1);
    check_int("content-type",
              memcmp(fields[2].name, "content-type", 12) == 0, 1);
}

/* ============================================================== */

int main(void) {
    test_udp_build_parse_roundtrip();
    test_udp_zero_payload();
    test_udp_overflow_buffer();
    test_udp_parse_rejects_bad_proto();
    test_udp_parse_rejects_bad_ip_csum();
    test_udp_parse_rejects_bad_udp_csum();
    test_udp_parse_rejects_zero_csum();
    test_udp_csum_never_zero();

    test_aes128_fips197_appendix_b();
    test_aes128_fips197_appendix_c1();

    test_aes128_gcm_nist();
    test_aes128_gcm_rfc9001();

    test_quic_varint();
    test_quic_initial_keys_a1();
    test_quic_initial_build_a3();
    test_quic_initial_parse_a2();

    test_frame_padding_and_ping();
    test_frame_crypto_roundtrip();
    test_frame_ack_roundtrip();
    test_frame_stream_roundtrip();
    test_frame_close_roundtrip();
    test_frame_decode_a3_payload();
    test_frame_decode_a2_payload();
    test_frame_decode_errors();

    test_rtt_first_sample();
    test_rtt_subsequent_samples();
    test_rtt_caps_ack_delay();
    test_loss_on_sent_and_ack();
    test_loss_packet_threshold();
    test_loss_time_threshold();
    test_loss_no_rtt_for_non_eliciting();
    test_loss_pto();
    test_loss_pto_resets_on_ack();

    test_cc_initial_window();
    test_cc_init();
    test_cc_slow_start();
    test_cc_loss_then_ca();
    test_cc_loss_floor_at_min_window();
    test_cc_persistent_congestion();
    test_flow_basic();
    test_flow_should_update();

    test_aux_reset_stream_roundtrip();
    test_aux_stop_sending_roundtrip();
    test_aux_max_frames_roundtrip();
    test_aux_blocked_frames_roundtrip();
    test_aux_new_conn_id_roundtrip();
    test_aux_retire_conn_id_and_path();
    test_special_stateless_reset_build_match();
    test_special_version_negotiation();
    test_special_idle_expired();

    test_tp_defaults();
    test_tp_encode_empty();
    test_tp_encode_decode_roundtrip();
    test_tp_decode_unknown_id_skipped();
    test_tp_decode_duplicate_rejected();
    test_tp_decode_truncated_rejected();
    test_tp_decode_illegal_values();
    test_tp_encode_validation();
    test_tp_encode_buffer_overflow();

    test_crypto_stream_rx_inorder();
    test_crypto_stream_rx_outoforder();
    test_crypto_stream_rx_duplicate();
    test_crypto_stream_rx_overlap_conflict();
    test_crypto_stream_rx_overflow();
    test_crypto_stream_rx_partial_consume();
    test_crypto_stream_tx_chunks();
    test_crypto_stream_tx_zero_budget();

    test_quic_keys_from_initial_secret();
    test_quic_keys_unsupported();
    test_quic_key_update();

    test_quic_tls_ext_emit_tp();
    test_quic_tls_ext_emit_overflow();
    test_quic_tls_ext_find_tp();
    test_quic_tls_ext_find_absent();
    test_quic_tls_ext_find_truncated();
    test_quic_tls_ext_find_duplicate();
    test_quic_tls_ext_round_trip();

    test_conn_recv_a2_client_initial();
    test_conn_recv_dcid_pin();
    test_conn_recv_rejects_short_garbage();
    test_conn_recv_rejects_aead_failure();

    test_conn_extract_ch_with_tp();
    test_conn_extract_ch_incomplete();
    test_conn_extract_ch_missing_tp();
    test_conn_extract_ch_malformed_tp();
    test_conn_extract_ch_not_handshake_type();

    test_conn_emit_initial_basic();
    test_conn_emit_initial_chunks();
    test_conn_emit_initial_no_pending();
    test_conn_emit_initial_no_peer_addrs();

    test_handshake_pkt_round_trip();
    test_handshake_pkt_rejects_initial_type();
    test_handshake_pkt_rejects_bad_version();

    test_conn_install_handshake_secrets();
    test_conn_install_handshake_secrets_idempotent();
    test_conn_emit_handshake_round_trip();
    test_conn_emit_handshake_no_keys();
    test_conn_recv_handshake_round_trip();
    test_conn_recv_handshake_rejects_initial_type();
    test_conn_recv_handshake_rejects_no_keys();

    test_drive_server_handshake_happy();
    test_drive_rejects_no_x25519();
    test_drive_rejects_bad_args();

    test_finish_handshake_round_trip();
    test_finish_rejects_bad_verify();
    test_finish_rejects_no_state();
    test_finish_rejects_short_buffer();

    test_short_pkt_round_trip();
    test_short_pkt_rejects_long_form();
    test_short_pkt_rejects_clear_fixed();
    test_short_pkt_aead_failure();
    test_conn_emit_recv_app_round_trip();
    test_conn_emit_app_no_keys();
    test_conn_recv_app_no_keys();

    /* phase 6b */
    test_stream_in_order();
    test_stream_out_of_order();
    test_stream_duplicate();
    test_stream_fin_size_change();
    test_stream_data_past_fin();
    test_stream_fin_smaller_than_staged();
    test_stream_overflow_capacity();
    test_stream_empty_fin();
    test_conn_recv_app_dispatches_stream();
    test_conn_recv_app_rejects_new_token();
    test_conn_recv_app_rejects_handshake_done();
    test_conn_recv_app_stream_overflow_slots();

    /* phase 6c — HTTP/3 framing */
    test_h3_classify();
    test_h3_encode_decode_data();
    test_h3_decode_partial();
    test_h3_decode_grease();
    test_h3_decode_reserved();
    test_h3_settings_round_trip();
    test_h3_settings_truncated();
    test_h3_encode_overflow();

    /* phase 6d1 — QPACK static decoder */
    test_qpack_static_lookup();
    test_qpack_decode_indexed();
    test_qpack_decode_literal_with_static_name();
    test_qpack_decode_literal_with_literal_name();
    test_qpack_decode_rejects_huffman();
    test_qpack_decode_rejects_dynamic();
    test_qpack_decode_rejects_nonzero_ric();
    test_qpack_decode_truncated();
    test_qpack_encode_oor_index();
    test_qpack_realistic_response();

    printf("\n=== RESULTS: PASS=%d FAIL=%d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
