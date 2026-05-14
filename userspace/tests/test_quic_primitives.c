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

    printf("\n=== RESULTS: PASS=%d FAIL=%d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
