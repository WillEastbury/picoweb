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

    printf("\n=== RESULTS: PASS=%d FAIL=%d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
