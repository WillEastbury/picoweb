/*
 * Tests for the userspace TLS crypto primitives.
 *
 * Every vector in this file traces back to a published RFC or NIST
 * standard. Failure here means a wire-format incompatibility — DO NOT
 * adjust the vectors.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/ed25519.h"
#include "../crypto/hmac.h"
#include "../crypto/hkdf.h"
#include "../crypto/chacha20.h"
#include "../crypto/poly1305.h"
#include "../crypto/chacha20_poly1305.h"
#include "../crypto/x25519.h"
#include "../crypto/cpuid.h"
#include "../crypto/pool.h"
#include "../tls/keysched.h"
#include "../tls/record.h"
#include "../tls/pem.h"
#include "../tls/cert.h"
#include "../tls/handshake.h"
#include "../tls/engine.h"
#include "../tls/ticket_store.h"
#include "../crypto/x25519.h"
#include "../tcp/ip.h"
#include "../tcp/tcp.h"
#include "../iov.h"
#include "../dispatch.h"
#include "../conn.h"

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

/* ============================================================== */
/* SHA-256 — NIST CAVP / FIPS 180-4 vectors.                      */
/* ============================================================== */
static void test_sha256(void) {
    printf("== SHA-256 ==\n");

    /* RFC 6234 §8.5 vector 1 */
    uint8_t want1[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    uint8_t got[32];
    sha256("abc", 3, got);
    check_eq("SHA-256(\"abc\")", got, want1, 32);

    /* RFC 6234 §8.5 vector 2 */
    uint8_t want2[32] = {
        0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
        0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
    };
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, got);
    check_eq("SHA-256(56-byte abc...)", got, want2, 32);

    /* Empty string: NIST */
    uint8_t want3[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    sha256("", 0, got);
    check_eq("SHA-256(\"\")", got, want3, 32);

    /* "a" * 1,000,000 — classic FIPS sample.
     * Stream the test through update() to exercise the buffering path. */
    sha256_ctx c;
    sha256_init(&c);
    uint8_t a_buf[1000];
    memset(a_buf, 'a', sizeof(a_buf));
    for (int i = 0; i < 1000; i++) sha256_update(&c, a_buf, sizeof(a_buf));
    sha256_final(&c, got);
    uint8_t want4[32] = {
        0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
        0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0
    };
    check_eq("SHA-256(\"a\"*1e6)", got, want4, 32);
}

/* ============================================================== */
/* SHA-512 — FIPS 180-4 sample vectors + RFC 6234 §8.5            */
/* ============================================================== */
static void test_sha512(void) {
    printf("== SHA-512 ==\n");
    uint8_t got[64];

    /* FIPS 180-4 short test: SHA-512("abc") */
    static const uint8_t want_abc[64] = {
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
    };
    sha512("abc", 3, got);
    check_eq("SHA-512(\"abc\")", got, want_abc, 64);

    /* Empty string (NIST FIPS 180-4 / RFC 6234) */
    static const uint8_t want_empty[64] = {
        0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
        0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
        0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
        0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
    };
    sha512("", 0, got);
    check_eq("SHA-512(\"\")", got, want_empty, 64);

    /* FIPS 180-4 long test: 112-byte 2-block message. Tests that
     * the second-block-needed padding path works (msg_len=112 > 111
     * so padding cannot fit in the same block as the 0x80). */
    static const char* msg2 =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    static const uint8_t want2[64] = {
        0x8e,0x95,0x9b,0x75,0xda,0xe3,0x13,0xda,0x8c,0xf4,0xf7,0x28,0x14,0xfc,0x14,0x3f,
        0x8f,0x77,0x79,0xc6,0xeb,0x9f,0x7f,0xa1,0x72,0x99,0xae,0xad,0xb6,0x88,0x90,0x18,
        0x50,0x1d,0x28,0x9e,0x49,0x00,0xf7,0xe4,0x33,0x1b,0x99,0xde,0xc4,0xb5,0x43,0x3a,
        0xc7,0xd3,0x29,0xee,0xb6,0xdd,0x26,0x54,0x5e,0x96,0xe5,0x5b,0x87,0x4b,0xe9,0x09
    };
    sha512(msg2, 112, got);
    check_eq("SHA-512(112-byte abc...)", got, want2, 64);

    /* Million 'a's via streaming update — exercises the buffering
     * path and multi-block compression. */
    sha512_ctx c;
    sha512_init(&c);
    uint8_t a_buf[1000];
    memset(a_buf, 'a', sizeof(a_buf));
    for (int i = 0; i < 1000; i++) sha512_update(&c, a_buf, sizeof(a_buf));
    sha512_final(&c, got);
    static const uint8_t want_a1m[64] = {
        0xe7,0x18,0x48,0x3d,0x0c,0xe7,0x69,0x64,0x4e,0x2e,0x42,0xc7,0xbc,0x15,0xb4,0x63,
        0x8e,0x1f,0x98,0xb1,0x3b,0x20,0x44,0x28,0x56,0x32,0xa8,0x03,0xaf,0xa9,0x73,0xeb,
        0xde,0x0f,0xf2,0x44,0x87,0x7e,0xa6,0x0a,0x4c,0xb0,0x43,0x2c,0xe5,0x77,0xc3,0x1b,
        0xeb,0x00,0x9c,0x5c,0x2c,0x49,0xaa,0x2e,0x4e,0xad,0xb2,0x17,0xad,0x8c,0xc0,0x9b
    };
    check_eq("SHA-512(\"a\"*1e6)", got, want_a1m, 64);

    /* Streaming-vs-one-shot equivalence test: hash a 200-byte input
     * one byte at a time and check it matches the one-shot. Catches
     * any buffer-boundary bugs in update() (we have a 128-byte block,
     * so a 200-byte input crosses one boundary). */
    uint8_t blob[200];
    for (int i = 0; i < 200; i++) blob[i] = (uint8_t)(i * 31 + 7);
    uint8_t one_shot[64], streamed[64];
    sha512(blob, sizeof(blob), one_shot);
    sha512_ctx s;
    sha512_init(&s);
    for (int i = 0; i < 200; i++) sha512_update(&s, blob + i, 1);
    sha512_final(&s, streamed);
    check_eq("SHA-512 byte-stream == one-shot", streamed, one_shot, 64);

    /* Block-boundary regression: hash exactly one block (128 bytes)
     * and exactly two blocks (256 bytes), verify against one-shot.
     * A bug in the update() "consume full blocks" loop would show. */
    uint8_t blk[256];
    for (int i = 0; i < 256; i++) blk[i] = (uint8_t)i;
    uint8_t a128_one[64], a128_stream[64];
    sha512(blk, 128, a128_one);
    sha512_init(&s);
    sha512_update(&s, blk, 64);
    sha512_update(&s, blk + 64, 64);
    sha512_final(&s, a128_stream);
    check_eq("SHA-512 128B split-update", a128_stream, a128_one, 64);

    uint8_t a256_one[64], a256_stream[64];
    sha512(blk, 256, a256_one);
    sha512_init(&s);
    sha512_update(&s, blk, 100);
    sha512_update(&s, blk + 100, 156);
    sha512_final(&s, a256_stream);
    check_eq("SHA-512 256B unaligned-split-update", a256_stream, a256_one, 64);
}

/* ============================================================== */
/* HMAC-SHA256 — RFC 4231 §4 vectors                              */
/* ============================================================== */
static void test_hmac_sha256(void) {
    printf("== HMAC-SHA256 ==\n");

    /* Test Case 1 */
    uint8_t key1[20]; memset(key1, 0x0b, sizeof(key1));
    uint8_t got[32];
    hmac_sha256(key1, sizeof(key1), "Hi There", 8, got);
    uint8_t want1[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };
    check_eq("RFC 4231 case 1", got, want1, 32);

    /* Test Case 2 */
    hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, got);
    uint8_t want2[32] = {
        0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
        0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
    };
    check_eq("RFC 4231 case 2", got, want2, 32);

    /* Test Case 3 — 20-byte 0xaa key, 50-byte 0xdd data */
    uint8_t key3[20]; memset(key3, 0xaa, sizeof(key3));
    uint8_t data3[50]; memset(data3, 0xdd, sizeof(data3));
    hmac_sha256(key3, sizeof(key3), data3, sizeof(data3), got);
    uint8_t want3[32] = {
        0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,0x85,0x4d,0xb8,0xeb,0xd0,0x91,0x81,0xa7,
        0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe
    };
    check_eq("RFC 4231 case 3", got, want3, 32);
}

/* ============================================================== */
/* HKDF-SHA256 — RFC 5869 §A.1 vector                            */
/* ============================================================== */
static void test_hkdf(void) {
    printf("== HKDF-SHA256 ==\n");

    uint8_t ikm[22];  memset(ikm, 0x0b, sizeof(ikm));
    uint8_t salt[13] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    uint8_t prk[32];
    hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
    uint8_t want_prk[32] = {
        0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
        0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5
    };
    check_eq("RFC 5869 A.1 PRK", prk, want_prk, 32);

    uint8_t okm[42];
    hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm));
    uint8_t want_okm[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };
    check_eq("RFC 5869 A.1 OKM", okm, want_okm, 42);
}

/* ============================================================== */
/* ChaCha20 — RFC 8439 §2.4.2                                     */
/* ============================================================== */
static void test_chacha20(void) {
    printf("== ChaCha20 ==\n");

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x4a, 0x00,0x00,0x00,0x00
    };
    const char pt[] = "Ladies and Gentlemen of the class of '99: "
                      "If I could offer you only one tip for the future, "
                      "sunscreen would be it.";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t want_ct[114] = {
        0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
        0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
        0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
        0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8,
        0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,
        0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
        0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,
        0x87,0x4d
    };
    uint8_t ct[200];
    chacha20_xor(key, 1, nonce, (const uint8_t*)pt, ct, pt_len);
    check_eq("RFC 8439 2.4.2 ciphertext", ct, want_ct, pt_len);
}

/* ============================================================== */
/* Poly1305 — RFC 8439 §2.5.2                                     */
/* ============================================================== */
static void test_poly1305(void) {
    printf("== Poly1305 ==\n");

    uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    const char msg[] = "Cryptographic Forum Research Group";
    uint8_t want[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
    };
    uint8_t got[16];
    poly1305(key, (const uint8_t*)msg, sizeof(msg) - 1, got);
    check_eq("RFC 8439 2.5.2 tag", got, want, 16);
}

/* ============================================================== */
/* ChaCha20-Poly1305 AEAD — RFC 8439 §2.8.2                       */
/* ============================================================== */
static void test_aead_chacha20_poly1305(void) {
    printf("== ChaCha20-Poly1305 AEAD ==\n");

    const char pt[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t aad[12] = {0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
    };

    uint8_t ct[200], tag[16];
    aead_chacha20_poly1305_seal(key, nonce, aad, sizeof(aad),
                                (const uint8_t*)pt, pt_len, ct, tag);

    uint8_t want_ct[114] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16
    };
    uint8_t want_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
    };
    check_eq("AEAD ciphertext", ct, want_ct, pt_len);
    check_eq("AEAD tag", tag, want_tag, 16);

    /* Round-trip. */
    uint8_t pt2[200];
    int rc = aead_chacha20_poly1305_open(key, nonce, aad, sizeof(aad),
                                         ct, pt_len, tag, pt2);
    if (rc == 0 && memcmp(pt2, pt, pt_len) == 0) {
        printf("  PASS: AEAD open round-trip\n"); g_pass++;
    } else {
        printf("  FAIL: AEAD open rc=%d\n", rc); g_fail++;
    }

    /* Tampering must fail. */
    uint8_t tag_bad[16];
    memcpy(tag_bad, tag, 16); tag_bad[0] ^= 1;
    rc = aead_chacha20_poly1305_open(key, nonce, aad, sizeof(aad),
                                     ct, pt_len, tag_bad, pt2);
    if (rc == -1) { printf("  PASS: tampered tag rejected\n"); g_pass++; }
    else          { printf("  FAIL: tampered tag accepted\n");  g_fail++; }
}

/* ============================================================== */
/* X25519 — RFC 7748 §5.2 + §6.1                                  */
/* ============================================================== */
static void test_x25519(void) {
    printf("== X25519 ==\n");

    /* §5.2 vector 1 */
    uint8_t scalar1[32], u1[32], want1[32], got[32];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
          scalar1, 32);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
          u1, 32);
    unhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
          want1, 32);
    x25519(got, scalar1, u1);
    check_eq("RFC 7748 5.2 vector 1", got, want1, 32);

    /* §5.2 vector 2 */
    uint8_t scalar2[32], u2[32], want2[32];
    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
          scalar2, 32);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
          u2, 32);
    unhex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
          want2, 32);
    x25519(got, scalar2, u2);
    check_eq("RFC 7748 5.2 vector 2", got, want2, 32);

    /* §6.1: ECDH round-trip — Alice and Bob compute shared secret. */
    uint8_t alice_priv[32], alice_pub[32], bob_priv[32], bob_pub[32];
    uint8_t want_shared[32];

    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
          alice_priv, 32);
    unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
          alice_pub, 32);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
          bob_priv, 32);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
          bob_pub, 32);
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
          want_shared, 32);

    /* Verify that scalar*base = pub. */
    uint8_t alice_pub_check[32], bob_pub_check[32];
    x25519(alice_pub_check, alice_priv, X25519_BASE_POINT);
    check_eq("Alice scalar*base = pub", alice_pub_check, alice_pub, 32);
    x25519(bob_pub_check, bob_priv, X25519_BASE_POINT);
    check_eq("Bob   scalar*base = pub", bob_pub_check, bob_pub, 32);

    uint8_t shared_a[32], shared_b[32];
    x25519(shared_a, alice_priv, bob_pub);
    x25519(shared_b, bob_priv, alice_pub);
    check_eq("Alice shared secret", shared_a, want_shared, 32);
    check_eq("Bob   shared secret", shared_b, want_shared, 32);
}

/* ============================================================== */
/* Ed25519 — RFC 8032 §7.1 test vectors.                          */
/* ============================================================== */
static void test_ed25519(void) {
    printf("== Ed25519 (RFC 8032 §7.1) ==\n");

    /* ---- TEST 1: empty message ---- */
    uint8_t seed1[32], pk1_want[32], sig1_want[64];
    unhex("9d61b19deffd5a60ba844af492ec2cc4"
          "4449c5697b326919703bac031cae7f60", seed1, 32);
    unhex("d75a980182b10ab7d54bfed3c964073a"
          "0ee172f3daa62325af021a68f707511a", pk1_want, 32);
    unhex("e5564300c360ac729086e2cc806e828a"
          "84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
          "1cf9b46bd25bf5f0595bbe24655141438e7a100b", sig1_want, 64);

    uint8_t pk1_got[32], sig1_got[64];
    ed25519_pubkey_from_seed(pk1_got, seed1);
    check_eq("RFC8032 TEST1 pubkey", pk1_got, pk1_want, 32);

    ed25519_sign(sig1_got, NULL, 0, seed1, pk1_want);
    check_eq("RFC8032 TEST1 sign  ", sig1_got, sig1_want, 64);

    if (ed25519_verify(sig1_want, NULL, 0, pk1_want) == 1) {
        printf("  PASS: RFC8032 TEST1 verify\n"); g_pass++;
    } else {
        printf("  FAIL: RFC8032 TEST1 verify\n"); g_fail++;
    }

    /* ---- TEST 2: 1-byte message 0x72 ---- */
    uint8_t seed2[32], pk2_want[32], sig2_want[64];
    uint8_t msg2[1] = { 0x72 };
    unhex("4ccd089b28ff96da9db6c346ec114e0f"
          "5b8a319f35aba624da8cf6ed4fb8a6fb", seed2, 32);
    unhex("3d4017c3e843895a92b70aa74d1b7ebc"
          "9c982ccf2ec4968cc0cd55f12af4660c", pk2_want, 32);
    unhex("92a009a9f0d4cab8720e820b5f642540"
          "a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613"
          "d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", sig2_want, 64);

    uint8_t pk2_got[32], sig2_got[64];
    ed25519_pubkey_from_seed(pk2_got, seed2);
    check_eq("RFC8032 TEST2 pubkey", pk2_got, pk2_want, 32);

    ed25519_sign(sig2_got, msg2, 1, seed2, pk2_want);
    check_eq("RFC8032 TEST2 sign  ", sig2_got, sig2_want, 64);

    if (ed25519_verify(sig2_want, msg2, 1, pk2_want) == 1) {
        printf("  PASS: RFC8032 TEST2 verify\n"); g_pass++;
    } else {
        printf("  FAIL: RFC8032 TEST2 verify\n"); g_fail++;
    }

    /* ---- TEST 3: 2-byte message af82 ---- */
    uint8_t seed3[32], pk3_want[32], sig3_want[64];
    uint8_t msg3[2] = { 0xaf, 0x82 };
    unhex("c5aa8df43f9f837bedb7442f31dcb7b1"
          "66d38535076f094b85ce3a2e0b4458f7", seed3, 32);
    unhex("fc51cd8e6218a1a38da47ed00230f058"
          "0816ed13ba3303ac5deb911548908025", pk3_want, 32);
    unhex("6291d657deec24024827e69c3abe01a3"
          "0ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760"
          "984dc6594a7c15e9716ed28dc027beceea1ec40a", sig3_want, 64);

    uint8_t pk3_got[32], sig3_got[64];
    ed25519_pubkey_from_seed(pk3_got, seed3);
    check_eq("RFC8032 TEST3 pubkey", pk3_got, pk3_want, 32);

    ed25519_sign(sig3_got, msg3, 2, seed3, pk3_want);
    check_eq("RFC8032 TEST3 sign  ", sig3_got, sig3_want, 64);

    if (ed25519_verify(sig3_want, msg3, 2, pk3_want) == 1) {
        printf("  PASS: RFC8032 TEST3 verify\n"); g_pass++;
    } else {
        printf("  FAIL: RFC8032 TEST3 verify\n"); g_fail++;
    }

    /* ---- Sign-verify roundtrip on a 200-byte message ---- */
    uint8_t big_msg[200];
    for (int i = 0; i < 200; i++) big_msg[i] = (uint8_t)(i ^ 0x5a);
    uint8_t sig_rt[64];
    ed25519_sign(sig_rt, big_msg, 200, seed3, pk3_want);
    if (ed25519_verify(sig_rt, big_msg, 200, pk3_want) == 1) {
        printf("  PASS: sign-verify roundtrip (200 B)\n"); g_pass++;
    } else {
        printf("  FAIL: sign-verify roundtrip (200 B)\n"); g_fail++;
    }

    /* ---- Bit-flip in signature must fail ---- */
    uint8_t sig_bad[64];
    memcpy(sig_bad, sig_rt, 64);
    sig_bad[10] ^= 0x01;
    if (ed25519_verify(sig_bad, big_msg, 200, pk3_want) == 0) {
        printf("  PASS: bit-flip in sig[10] rejected\n"); g_pass++;
    } else {
        printf("  FAIL: bit-flip in sig[10] accepted\n"); g_fail++;
    }

    /* ---- Bit-flip in pubkey must fail ---- */
    uint8_t pk_bad[32];
    memcpy(pk_bad, pk3_want, 32);
    pk_bad[5] ^= 0x40;
    if (ed25519_verify(sig_rt, big_msg, 200, pk_bad) == 0) {
        printf("  PASS: bit-flip in pk[5] rejected\n"); g_pass++;
    } else {
        printf("  FAIL: bit-flip in pk[5] accepted\n"); g_fail++;
    }

    /* ---- Bit-flip in message must fail ---- */
    uint8_t msg_bad[200];
    memcpy(msg_bad, big_msg, 200);
    msg_bad[100] ^= 0x80;
    if (ed25519_verify(sig_rt, msg_bad, 200, pk3_want) == 0) {
        printf("  PASS: bit-flip in msg[100] rejected\n"); g_pass++;
    } else {
        printf("  FAIL: bit-flip in msg[100] accepted\n"); g_fail++;
    }

    /* ---- Non-canonical R: y_bytes == p exactly must be rejected.
     *   p = 2^255 - 19 → LE bytes = ed,ff,ff,...,ff,7f. We patch the
     *   R-half of a real signature to that value; verify must say 0
     *   (point decode rejects non-canonical y). */
    uint8_t sig_noncanon[64];
    memcpy(sig_noncanon, sig_rt, 64);
    sig_noncanon[0]  = 0xed;
    for (int i = 1; i < 31; i++) sig_noncanon[i] = 0xff;
    sig_noncanon[31] = 0x7f;
    if (ed25519_verify(sig_noncanon, big_msg, 200, pk3_want) == 0) {
        printf("  PASS: non-canonical R (y==p) rejected\n"); g_pass++;
    } else {
        printf("  FAIL: non-canonical R (y==p) accepted\n"); g_fail++;
    }
}

/* ============================================================== */
/* TLS 1.3 key schedule — RFC 8448 §3 (PSK=0 handshake)           */
/* ============================================================== */
static void test_tls13_keysched(void) {
    printf("== TLS 1.3 key schedule (RFC 8448 §3) ==\n");

    /* RFC 8448 §3 begins with a non-PSK handshake. The Early Secret
     * derivation uses PSK=0 (32 zero bytes) and salt=0:
     *
     *   early_secret = HKDF-Extract(0, 0)
     *                = 33ad0a1c607ec03b09e6cd9893680ce2
     *                  10adf300aa1f2660e1b22e10f170f9 2a
     */
    uint8_t zero32[32] = {0};
    uint8_t early_secret[32];
    hkdf_extract(NULL, 0, zero32, 32, early_secret);
    uint8_t want_early[32];
    unhex("33ad0a1c607ec03b09e6cd9893680ce2"
          "10adf300aa1f2660e1b22e10f170f92a", want_early, 32);
    check_eq("RFC 8448 early_secret", early_secret, want_early, 32);

    /* derived_secret = Derive-Secret(early_secret, "derived", "")
     *                = 6f2615a108c702c5678f54fc9dbab697
     *                  16c076189c48250cebeac3576c3611ba
     */
    uint8_t derived[32];
    tls13_derive_secret(early_secret, "derived", NULL, 0, derived);
    uint8_t want_derived[32];
    unhex("6f2615a108c702c5678f54fc9dbab697"
          "16c076189c48250cebeac3576c3611ba", want_derived, 32);
    check_eq("RFC 8448 derived (from early_secret)", derived, want_derived, 32);

    /* HKDF-Expand-Label round-trip: derive a 32-byte key from
     * early_secret with label "c hs traffic" and an empty context.
     * Per RFC 8446 §7.1 this is one of the standard handshake
     * traffic secrets — we verify shape by re-deriving using two
     * different paths and comparing. */
    uint8_t out_a[32], out_b[32];
    tls13_hkdf_expand_label(early_secret, "c hs traffic",
                            NULL, 0, out_a, 32);
    tls13_hkdf_expand_label(early_secret, "c hs traffic",
                            NULL, 0, out_b, 32);
    check_eq("HKDF-Expand-Label deterministic", out_a, out_b, 32);

    /* derive_traffic_keys: shape test — the same traffic_secret must
     * always produce the same (key, iv) pair. */
    uint8_t k1[32], iv1[12], k2[32], iv2[12];
    tls13_derive_traffic_keys(early_secret, k1, iv1);
    tls13_derive_traffic_keys(early_secret, k2, iv2);
    check_eq("derive_traffic_keys: key reproducible", k1, k2, 32);
    check_eq("derive_traffic_keys: iv reproducible",  iv1, iv2, 12);
}

/* ============================================================== */
/* TLS 1.3 record layer round-trip                                */
/* ============================================================== */
static void test_tls13_record(void) {
    printf("== TLS 1.3 record layer round-trip ==\n");

    /* Pick arbitrary key + iv; the wire format is what matters. */
    tls_record_dir_t tx, rx;
    memset(&tx, 0, sizeof(tx));
    memset(&rx, 0, sizeof(rx));
    for (int i = 0; i < 32; i++) { tx.key[i] = (uint8_t)i; rx.key[i] = (uint8_t)i; }
    for (int i = 0; i < 12; i++) {
        tx.static_iv[i] = (uint8_t)(0xa0 + i);
        rx.static_iv[i] = (uint8_t)(0xa0 + i);
    }

    const char* msg1 = "GET / HTTP/1.1\r\nHost: picoweb\r\n\r\n";
    const char* msg2 = "GET /health HTTP/1.1\r\nHost: picoweb\r\n\r\n";
    uint8_t wire[2048];

    /* Seal first record. */
    size_t w1 = tls13_seal_record(&tx, TLS_CT_APPLICATION_DATA,
                                  TLS_CT_APPLICATION_DATA,
                                  (const uint8_t*)msg1, strlen(msg1),
                                  wire, sizeof(wire));
    if (w1 == 0) { printf("  FAIL: seal returned 0\n"); g_fail++; return; }

    /* Open it back. */
    tls_content_type_t got_type;
    uint8_t* got_pt; size_t got_pt_len;
    int rc = tls13_open_record(&rx, wire, w1, &got_type, &got_pt, &got_pt_len);
    if (rc != 0) { printf("  FAIL: open record 1 (rc=%d)\n", rc); g_fail++; return; }
    if (got_type == TLS_CT_APPLICATION_DATA &&
        got_pt_len == strlen(msg1) &&
        memcmp(got_pt, msg1, got_pt_len) == 0) {
        printf("  PASS: record 1 round-trips (%zu B)\n", got_pt_len);
        g_pass++;
    } else {
        printf("  FAIL: record 1 round-trip\n"); g_fail++;
    }

    /* Seal a second record — sequence number must advance. */
    size_t w2 = tls13_seal_record(&tx, TLS_CT_APPLICATION_DATA,
                                  TLS_CT_APPLICATION_DATA,
                                  (const uint8_t*)msg2, strlen(msg2),
                                  wire, sizeof(wire));
    rc = tls13_open_record(&rx, wire, w2, &got_type, &got_pt, &got_pt_len);
    if (rc == 0 && got_pt_len == strlen(msg2) &&
        memcmp(got_pt, msg2, got_pt_len) == 0) {
        printf("  PASS: record 2 round-trips (seq advance OK)\n");
        g_pass++;
    } else {
        printf("  FAIL: record 2 round-trip rc=%d\n", rc); g_fail++;
    }

    /* Seq mismatch: roll the rx side forward and prove it fails. */
    tls_record_dir_t rx_skip = rx;
    rx_skip.seq++;
    size_t w3 = tls13_seal_record(&tx, TLS_CT_APPLICATION_DATA,
                                  TLS_CT_APPLICATION_DATA,
                                  (const uint8_t*)msg1, strlen(msg1),
                                  wire, sizeof(wire));
    rc = tls13_open_record(&rx_skip, wire, w3, &got_type, &got_pt, &got_pt_len);
    if (rc == -1) { printf("  PASS: out-of-order record rejected\n"); g_pass++; }
    else          { printf("  FAIL: out-of-order accepted\n"); g_fail++; }

    /* Tamper test: flip a byte in the ciphertext. */
    rx.seq++;   /* match what was just rolled */
    size_t w4 = tls13_seal_record(&tx, TLS_CT_HANDSHAKE,
                                  TLS_CT_APPLICATION_DATA,
                                  (const uint8_t*)msg2, strlen(msg2),
                                  wire, sizeof(wire));
    wire[10] ^= 0x01;
    rc = tls13_open_record(&rx, wire, w4, &got_type, &got_pt, &got_pt_len);
    if (rc == -1) { printf("  PASS: tampered record rejected\n"); g_pass++; }
    else          { printf("  FAIL: tampered record accepted\n"); g_fail++; }
}

/* ============================================================== */
/* IPv4 + TCP build/parse round-trip                              */
/* ============================================================== */
static void test_ip_tcp(void) {
    printf("== IPv4 + TCP build/parse ==\n");

    const uint8_t payload[] = "hello tcp";
    tcp_seg_t out_seg = {
        .src_ip   = 0x0a000001u,        /* 10.0.0.1 */
        .dst_ip   = 0x0a000002u,        /* 10.0.0.2 */
        .src_port = 4242,
        .dst_port = 80,
        .seq      = 0xdeadbeefu,
        .ack      = 0xcafebabeu,
        .window   = 65535,
        .flags    = TCPF_PSH | TCPF_ACK,
        .payload  = payload,
        .payload_len = sizeof(payload) - 1,
    };
    uint8_t buf[256];
    size_t n = ip_tcp_build(buf, sizeof(buf), &out_seg);
    if (n == 0) { printf("  FAIL: build\n"); g_fail++; return; }

    tcp_seg_t parsed;
    int rc = ip_tcp_parse(buf, n, &parsed);
    if (rc != 0) { printf("  FAIL: parse rc=%d\n", rc); g_fail++; return; }

    if (parsed.src_ip == out_seg.src_ip &&
        parsed.dst_ip == out_seg.dst_ip &&
        parsed.src_port == out_seg.src_port &&
        parsed.dst_port == out_seg.dst_port &&
        parsed.seq == out_seg.seq &&
        parsed.ack == out_seg.ack &&
        parsed.flags == out_seg.flags &&
        parsed.payload_len == out_seg.payload_len &&
        memcmp(parsed.payload, payload, parsed.payload_len) == 0) {
        printf("  PASS: build/parse round-trip\n");
        g_pass++;
    } else {
        printf("  FAIL: round-trip mismatch\n"); g_fail++;
    }

    /* Tamper IPv4 header: should now fail csum. */
    buf[12] ^= 0x01;
    rc = ip_tcp_parse(buf, n, &parsed);
    if (rc == -1) { printf("  PASS: bad IPv4 csum rejected\n"); g_pass++; }
    else          { printf("  FAIL: bad IPv4 csum accepted\n"); g_fail++; }
    buf[12] ^= 0x01;            /* restore */

    /* Tamper TCP payload: should now fail TCP csum. */
    buf[IPV4_HEADER_LEN + TCP_HEADER_LEN + 0] ^= 0x80;
    rc = ip_tcp_parse(buf, n, &parsed);
    if (rc == -1) { printf("  PASS: bad TCP csum rejected\n"); g_pass++; }
    else          { printf("  FAIL: bad TCP csum accepted\n"); g_fail++; }
}

/* ============================================================== */
/* TCP state machine — passive open happy path                    */
/* ============================================================== */
typedef struct {
    tcp_seg_t segs[16];
    int       n;
} emit_log_t;

static void log_emit(const tcp_seg_t* seg, void* user) {
    emit_log_t* L = (emit_log_t*)user;
    if (L->n < (int)(sizeof(L->segs) / sizeof(L->segs[0]))) {
        L->segs[L->n++] = *seg;
    }
}

typedef struct {
    uint8_t  data[256];
    size_t   len;
} app_buf_t;

static void on_data(tcp_conn_t* c, const uint8_t* data, size_t len, void* user) {
    (void)c;
    app_buf_t* B = (app_buf_t*)user;
    if (B->len + len <= sizeof(B->data)) {
        memcpy(B->data + B->len, data, len);
        B->len += len;
    }
}

static void test_tcp_state(void) {
    printf("== TCP state machine (passive open happy path) ==\n");

    tcp_stack_t stack;
    tcp_listen(&stack, 0x0a000002u, 80);

    emit_log_t emit_log = {0};
    app_buf_t  app = {0};

    /* Client SYN. */
    tcp_seg_t syn = {0};
    syn.src_ip = 0x0a000001u; syn.dst_ip = 0x0a000002u;
    syn.src_port = 4242;     syn.dst_port = 80;
    syn.seq = 1000;          syn.flags = TCPF_SYN;
    syn.window = 65535;
    tcp_input(&stack, &syn, on_data, &app, log_emit, &emit_log);
    if (emit_log.n == 1 && (emit_log.segs[0].flags & (TCPF_SYN|TCPF_ACK)) == (TCPF_SYN|TCPF_ACK) &&
        emit_log.segs[0].ack == 1001) {
        printf("  PASS: SYN -> SYN+ACK\n"); g_pass++;
    } else {
        printf("  FAIL: SYN handshake (n=%d)\n", emit_log.n); g_fail++;
    }
    uint32_t srv_iss = emit_log.segs[0].seq;

    /* Client ACK + payload. */
    emit_log.n = 0;
    const char* http = "GET / HTTP/1.1\r\n";
    tcp_seg_t pkt = {0};
    pkt.src_ip = 0x0a000001u; pkt.dst_ip = 0x0a000002u;
    pkt.src_port = 4242;     pkt.dst_port = 80;
    pkt.seq = 1001;          pkt.ack = srv_iss + 1;
    pkt.flags = TCPF_ACK | TCPF_PSH;
    pkt.window = 65535;
    pkt.payload = (const uint8_t*)http;
    pkt.payload_len = strlen(http);
    tcp_input(&stack, &pkt, on_data, &app, log_emit, &emit_log);
    if (emit_log.n == 1 && (emit_log.segs[0].flags & TCPF_ACK) &&
        app.len == strlen(http) && memcmp(app.data, http, app.len) == 0) {
        printf("  PASS: ESTABLISHED + data delivered to app\n"); g_pass++;
    } else {
        printf("  FAIL: data delivery (emit.n=%d, app.len=%zu)\n",
               emit_log.n, app.len); g_fail++;
    }

    /* Server sends a response. */
    emit_log.n = 0;
    tcp_conn_t* srv = NULL;
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        if (stack.conns[i].state == TCP_ESTABLISHED) { srv = &stack.conns[i]; break; }
    }
    if (!srv) { printf("  FAIL: no ESTABLISHED conn\n"); g_fail++; return; }
    const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    int sent = tcp_send(srv, (const uint8_t*)resp, strlen(resp),
                        log_emit, &emit_log);
    if (sent == (int)strlen(resp) && emit_log.n == 1 &&
        emit_log.segs[0].payload_len == strlen(resp)) {
        printf("  PASS: server -> client data\n"); g_pass++;
    } else {
        printf("  FAIL: tcp_send sent=%d emit.n=%d\n", sent, emit_log.n); g_fail++;
    }

    /* Client FIN -> server should ACK + send its own FIN, end up LAST_ACK. */
    emit_log.n = 0;
    tcp_seg_t fin = {0};
    fin.src_ip = 0x0a000001u; fin.dst_ip = 0x0a000002u;
    fin.src_port = 4242;     fin.dst_port = 80;
    fin.seq = 1001 + strlen(http);
    fin.ack = srv->snd_nxt;
    fin.flags = TCPF_FIN | TCPF_ACK;
    fin.window = 65535;
    tcp_input(&stack, &fin, on_data, &app, log_emit, &emit_log);
    if (srv->state == TCP_LAST_ACK && emit_log.n >= 1) {
        printf("  PASS: FIN handled, state=LAST_ACK\n"); g_pass++;
    } else {
        printf("  FAIL: FIN handling state=%d emit.n=%d\n", srv->state, emit_log.n); g_fail++;
    }

    /* Final ACK from client closes the connection. */
    tcp_seg_t last = {0};
    last.src_ip = 0x0a000001u; last.dst_ip = 0x0a000002u;
    last.src_port = 4242;     last.dst_port = 80;
    last.seq = 1001 + strlen(http) + 1;
    last.ack = srv->snd_nxt;
    last.flags = TCPF_ACK;
    last.window = 65535;
    emit_log.n = 0;
    tcp_input(&stack, &last, on_data, &app, log_emit, &emit_log);
    if (srv->state == TCP_CLOSED) { printf("  PASS: connection CLOSED\n"); g_pass++; }
    else                          { printf("  FAIL: state=%d not CLOSED\n", srv->state); g_fail++; }
}

/* ============================================================== */
/* TCP zero-window flow control + persist probe handling          */
/* ============================================================== */
static void test_tcp_zero_window(void) {
    printf("== TCP zero-window flow control + persist probe ==\n");

    tcp_stack_t stack;
    tcp_listen(&stack, 0x0a000002u, 80);

    emit_log_t emit_log = {0};
    app_buf_t  app = {0};

    /* SYN -> SYN+ACK */
    tcp_seg_t syn = {0};
    syn.src_ip = 0x0a000001u; syn.dst_ip = 0x0a000002u;
    syn.src_port = 5050;     syn.dst_port = 80;
    syn.seq = 7000;          syn.flags = TCPF_SYN;
    tcp_input(&stack, &syn, on_data, &app, log_emit, &emit_log);
    uint32_t srv_iss = emit_log.segs[0].seq;

    /* Find the server PCB; cap rcv buffer to 8 bytes. */
    tcp_conn_t* srv = NULL;
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        if (stack.conns[i].state == TCP_SYN_RECEIVED) { srv = &stack.conns[i]; break; }
    }
    if (!srv) { printf("  FAIL: no SYN_RECEIVED PCB\n"); g_fail++; return; }
    tcp_set_rcv_buf_cap(srv, 8);

    /* Final ACK to reach ESTABLISHED. */
    emit_log.n = 0;
    tcp_seg_t ack = {0};
    ack.src_ip = 0x0a000001u; ack.dst_ip = 0x0a000002u;
    ack.src_port = 5050;     ack.dst_port = 80;
    ack.seq = 7001;          ack.ack = srv_iss + 1;
    ack.flags = TCPF_ACK;
    tcp_input(&stack, &ack, on_data, &app, log_emit, &emit_log);

    /* Send 8 bytes - exactly fills the buffer. ACK must advertise wnd=0. */
    emit_log.n = 0;
    tcp_seg_t pkt = {0};
    pkt.src_ip = 0x0a000001u; pkt.dst_ip = 0x0a000002u;
    pkt.src_port = 5050;     pkt.dst_port = 80;
    pkt.seq = 7001;          pkt.ack = srv_iss + 1;
    pkt.flags = TCPF_ACK | TCPF_PSH;
    pkt.payload = (const uint8_t*)"AAAAAAAA";
    pkt.payload_len = 8;
    tcp_input(&stack, &pkt, on_data, &app, log_emit, &emit_log);

    if (emit_log.n == 1 && emit_log.segs[0].window == 0 && app.len == 8)
         { printf("  PASS: full buffer -> ACK with window=0, data delivered\n"); g_pass++; }
    else { printf("  FAIL: emit.n=%d wnd=%u app.len=%zu\n",
                  emit_log.n, emit_log.segs[0].window, app.len); g_fail++; }

    /* Persist probe: peer sends 1 byte at next seq. We MUST drop it
     * (no app delivery, no rcv_nxt advance) and re-ACK with wnd=0. */
    emit_log.n = 0;
    size_t app_len_before = app.len;
    uint32_t rcv_nxt_before = srv->rcv_nxt;
    pkt.seq = 7009;
    pkt.payload = (const uint8_t*)"X";
    pkt.payload_len = 1;
    tcp_input(&stack, &pkt, on_data, &app, log_emit, &emit_log);

    if (emit_log.n == 1 && emit_log.segs[0].window == 0
        && emit_log.segs[0].ack == rcv_nxt_before
        && app.len == app_len_before
        && srv->rcv_nxt == rcv_nxt_before)
         { printf("  PASS: persist probe dropped + re-ACKed with wnd=0\n"); g_pass++; }
    else { printf("  FAIL: emit.n=%d wnd=%u ack=%u app.len=%zu rcv_nxt=%u\n",
                  emit_log.n, emit_log.segs[0].window,
                  emit_log.segs[0].ack, app.len, srv->rcv_nxt); g_fail++; }

    /* Drain the application buffer; tcp_rcv_consumed must emit a
     * window-update ACK because window opened from 0 -> 8. */
    emit_log.n = 0;
    app.len = 0;
    tcp_rcv_consumed(srv, 8, log_emit, &emit_log);

    if (emit_log.n == 1
        && (emit_log.segs[0].flags & TCPF_ACK)
        && emit_log.segs[0].window == 8)
         { printf("  PASS: window-update ACK emitted on 0->non-zero\n"); g_pass++; }
    else { printf("  FAIL: emit.n=%d wnd=%u flags=%02x\n",
                  emit_log.n, emit_log.segs[0].window,
                  emit_log.n ? emit_log.segs[0].flags : 0); g_fail++; }

    /* Calling tcp_rcv_consumed when window was already non-zero must
     * NOT emit (avoid spurious window updates). */
    emit_log.n = 0;
    /* Refill so we have something to drain. */
    tcp_set_rcv_buf_cap(srv, 8);
    srv->rcv_buf_used = 4;
    srv->rcv_wnd = tcp_advertised_wnd(srv);
    tcp_rcv_consumed(srv, 4, log_emit, &emit_log);
    if (emit_log.n == 0)
         { printf("  PASS: no spurious update when window already open\n"); g_pass++; }
    else { printf("  FAIL: emit.n=%d (want 0)\n", emit_log.n); g_fail++; }

    /* Default behaviour (cap=0) advertises 65535. */
    tcp_conn_t legacy = {0};
    if (tcp_advertised_wnd(&legacy) == 65535)
         { printf("  PASS: cap=0 -> legacy 65535 advertised window\n"); g_pass++; }
    else { printf("  FAIL: cap=0 wnd=%u\n", tcp_advertised_wnd(&legacy)); g_fail++; }
}

/* ============================================================== */
/* TCP retransmit + RFC 6298 RTO timer                            */
/* ============================================================== */
static void test_tcp_retransmit_rto(void) {
    printf("== TCP retransmit + RFC 6298 RTO ==\n");

    tcp_stack_t stack;
    tcp_listen(&stack, 0x0a000002u, 80);

    emit_log_t emit_log = {0};
    app_buf_t  app = {0};

    /* SYN -> SYN+ACK at t=10. */
    tcp_seg_t syn = {0};
    syn.src_ip = 0x0a000001u; syn.dst_ip = 0x0a000002u;
    syn.src_port = 6060;     syn.dst_port = 80;
    syn.seq = 5000;          syn.flags = TCPF_SYN;
    tcp_input_at(&stack, &syn, 10, on_data, &app, log_emit, &emit_log);
    uint32_t srv_iss = emit_log.segs[0].seq;

    tcp_conn_t* srv = NULL;
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        if (stack.conns[i].state == TCP_SYN_RECEIVED) { srv = &stack.conns[i]; break; }
    }
    if (!srv) { printf("  FAIL: no SYN_RECEIVED PCB\n"); g_fail++; return; }

    /* Final ACK -> ESTABLISHED. */
    emit_log.n = 0;
    tcp_seg_t ack = {0};
    ack.src_ip = 0x0a000001u; ack.dst_ip = 0x0a000002u;
    ack.src_port = 6060;     ack.dst_port = 80;
    ack.seq = 5001;          ack.ack = srv_iss + 1;
    ack.flags = TCPF_ACK;
    tcp_input_at(&stack, &ack, 20, NULL, NULL, log_emit, &emit_log);

    /* Send 5 bytes at t=100 with RTX tracking. */
    emit_log.n = 0;
    static const uint8_t hello[5] = {'h','e','l','l','o'};
    int sent = tcp_send_at(srv, hello, 5, 100, log_emit, &emit_log);
    uint32_t data_seq = emit_log.segs[0].seq;
    if (sent == 5 && srv->rtx_n == 1 && srv->rtx[0].seq == data_seq
        && srv->rtx[0].len == 5 && srv->rtx[0].tx_time_ms == 100)
         { printf("  PASS: tcp_send_at queues RTX entry\n"); g_pass++; }
    else { printf("  FAIL: sent=%d rtx_n=%u\n", sent, srv->rtx_n); g_fail++; }

    /* Initial RTO is TCP_RTO_INIT_MS == 1000. tcp_tick at t=900
     * (age=800 < 1000) must NOT retransmit. */
    emit_log.n = 0;
    tcp_tick(&stack, 900, log_emit, &emit_log);
    if (emit_log.n == 0)
         { printf("  PASS: tick before RTO does not retransmit\n"); g_pass++; }
    else { printf("  FAIL: spurious retransmit n=%d\n", emit_log.n); g_fail++; }

    /* Tick at t=1100 (age=1000 == rto): retransmit oldest. RTO doubles. */
    emit_log.n = 0;
    uint32_t rto_before = srv->rto_ms;
    tcp_tick(&stack, 1100, log_emit, &emit_log);
    if (emit_log.n == 1
        && emit_log.segs[0].seq == data_seq
        && emit_log.segs[0].payload_len == 5
        && srv->rtx[0].retrans == 1
        && srv->rto_ms == rto_before * 2)
         { printf("  PASS: RTO fired -> retransmit + RTO doubled (%u -> %u)\n",
                  rto_before, srv->rto_ms); g_pass++; }
    else { printf("  FAIL: n=%d seq=%u rto=%u (was %u) retrans=%u\n",
                  emit_log.n,
                  emit_log.n ? emit_log.segs[0].seq : 0,
                  srv->rto_ms, rto_before,
                  srv->rtx_n ? srv->rtx[0].retrans : 99); g_fail++; }

    /* Peer ACKs the data at t=1200. Karn: this ack came after a
     * retransmit so we must NOT take an RTT sample (srtt stays 0). */
    emit_log.n = 0;
    tcp_seg_t ack2 = ack;
    ack2.seq = 5001;
    ack2.ack = data_seq + 5;
    tcp_input_at(&stack, &ack2, 1200, NULL, NULL, log_emit, &emit_log);
    if (srv->rtx_n == 0 && srv->srtt_ms == 0)
         { printf("  PASS: ACK drains RTX, Karn skips retransmitted sample\n"); g_pass++; }
    else { printf("  FAIL: rtx_n=%u srtt=%u\n", srv->rtx_n, srv->srtt_ms); g_fail++; }

    /* Reset RTO so the next send doesn't use the doubled value. */
    srv->rto_ms = TCP_RTO_INIT_MS;

    /* New send + clean ACK should produce an RTT sample and update
     * SRTT/RTTVAR/RTO per RFC 6298 §2.2. */
    emit_log.n = 0;
    static const uint8_t world[5] = {'w','o','r','l','d'};
    tcp_send_at(srv, world, 5, 2000, log_emit, &emit_log);
    uint32_t world_seq = emit_log.segs[0].seq;

    emit_log.n = 0;
    ack2.ack = world_seq + 5;
    tcp_input_at(&stack, &ack2, 2050, NULL, NULL, log_emit, &emit_log);
    /* RTT = 50 ms. First sample: SRTT=50, RTTVAR=25, RTO=SRTT+4*RTTVAR=150,
     * but clamped to TCP_RTO_MIN_MS (200). */
    if (srv->srtt_ms == 50 && srv->rttvar_ms == 25 && srv->rto_ms == 200)
         { printf("  PASS: first RTT sample sets SRTT=50 RTTVAR=25 RTO=200\n"); g_pass++; }
    else { printf("  FAIL: srtt=%u rttvar=%u rto=%u\n",
                  srv->srtt_ms, srv->rttvar_ms, srv->rto_ms); g_fail++; }

    /* RTX queue cap: fill it up; an extra send_at must refuse. */
    srv->rtx_n = TCP_RTX_QUEUE_MAX;
    int rc = tcp_send_at(srv, hello, 5, 3000, log_emit, &emit_log);
    if (rc == -1)
         { printf("  PASS: RTX queue full -> tcp_send_at returns -1\n"); g_pass++; }
    else { printf("  FAIL: rc=%d (want -1)\n", rc); g_fail++; }
}

/* ============================================================== */
/* TCP NewReno congestion control (RFC 5681)                      */
/* ============================================================== */
static void test_tcp_congestion_control(void) {
    printf("== TCP NewReno congestion control ==\n");

    tcp_stack_t stack;
    tcp_listen(&stack, 0x0a000002u, 80);
    emit_log_t emit_log = {0};
    app_buf_t  app = {0};

    /* Establish. */
    tcp_seg_t syn = {0};
    syn.src_ip = 0x0a000001u; syn.dst_ip = 0x0a000002u;
    syn.src_port = 7070;     syn.dst_port = 80;
    syn.seq = 9000;          syn.flags = TCPF_SYN;
    syn.window = 65535;
    tcp_input_at(&stack, &syn, 10, on_data, &app, log_emit, &emit_log);
    uint32_t srv_iss = emit_log.segs[0].seq;

    tcp_conn_t* srv = NULL;
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        if (stack.conns[i].state == TCP_SYN_RECEIVED) { srv = &stack.conns[i]; break; }
    }
    if (!srv) { printf("  FAIL: no PCB\n"); g_fail++; return; }

    /* Initial cwnd is IW10 (10 * MSS) per RFC 6928. */
    if (srv->cwnd == TCP_INIT_CWND && srv->ssthresh == 0xffffffffu)
         { printf("  PASS: initial cwnd=IW10=%u ssthresh=infinity\n", srv->cwnd); g_pass++; }
    else { printf("  FAIL: cwnd=%u ssthresh=%u\n", srv->cwnd, srv->ssthresh); g_fail++; }

    /* Final ACK. */
    emit_log.n = 0;
    tcp_seg_t ack = {0};
    ack.src_ip = 0x0a000001u; ack.dst_ip = 0x0a000002u;
    ack.src_port = 7070;     ack.dst_port = 80;
    ack.seq = 9001;          ack.ack = srv_iss + 1;
    ack.flags = TCPF_ACK;    ack.window = 65535;
    tcp_input_at(&stack, &ack, 20, NULL, NULL, log_emit, &emit_log);

    /* tcp_send_window should equal min(cwnd, snd_wnd). snd_wnd=65535,
     * cwnd=14600, flight=0 -> 14600. */
    uint32_t sw = tcp_send_window(srv);
    if (sw == TCP_INIT_CWND)
         { printf("  PASS: send_window=cwnd when snd_wnd is large (%u)\n", sw); g_pass++; }
    else { printf("  FAIL: send_window=%u\n", sw); g_fail++; }

    /* Slow-start growth: send 100 bytes, ACK it. cwnd grows by min(100,MSS)=100. */
    static const uint8_t buf100[100] = {0};
    emit_log.n = 0;
    tcp_send_at(srv, buf100, 100, 100, log_emit, &emit_log);
    uint32_t data_seq = emit_log.segs[0].seq;
    uint32_t cwnd_before = srv->cwnd;
    emit_log.n = 0;
    ack.seq = 9001; ack.ack = data_seq + 100;
    tcp_input_at(&stack, &ack, 150, NULL, NULL, log_emit, &emit_log);
    if (srv->cwnd == cwnd_before + 100u)
         { printf("  PASS: slow-start: cwnd %u -> %u (+100)\n", cwnd_before, srv->cwnd); g_pass++; }
    else { printf("  FAIL: cwnd=%u (want %u)\n", srv->cwnd, cwnd_before + 100u); g_fail++; }

    /* Send-window respects cwnd: try to send more than send_window. */
    srv->cwnd = TCP_MSS;       /* shrink artificially */
    srv->snd_wnd = 65535u;
    /* flight=0, so window = MSS = 1460. Try 1500 bytes -> refused. */
    static uint8_t big[1500] = {0};
    emit_log.n = 0;
    int rc2 = tcp_send_at(srv, big, 1500, 200, log_emit, &emit_log);
    if (rc2 == -1 && emit_log.n == 0)
         { printf("  PASS: send > send_window refused\n"); g_pass++; }
    else { printf("  FAIL: rc=%d emit.n=%d\n", rc2, emit_log.n); g_fail++; }

    /* 1460 (==window) is accepted. */
    rc2 = tcp_send_at(srv, big, TCP_MSS, 200, log_emit, &emit_log);
    if (rc2 == (int)TCP_MSS)
         { printf("  PASS: send == send_window accepted\n"); g_pass++; }
    else { printf("  FAIL: rc=%d\n", rc2); g_fail++; }
    /* Drain. */
    uint32_t mss_seq = srv->snd_una;
    ack.ack = mss_seq + TCP_MSS;
    tcp_input_at(&stack, &ack, 250, NULL, NULL, log_emit, &emit_log);

    /* Fast retransmit on 3 duplicate ACKs. Set up: send 3 segments,
     * have peer ACK only the first, then send 3 dupacks. */
    srv->cwnd = TCP_INIT_CWND;
    srv->ssthresh = 0xffffffffu;
    srv->rtx_n = 0;
    srv->dupack_n = 0;
    srv->in_recovery = 0;

    static const uint8_t segA[200] = {0};
    static const uint8_t segB[200] = {0};
    static const uint8_t segC[200] = {0};
    emit_log.n = 0;
    tcp_send_at(srv, segA, 200, 300, log_emit, &emit_log);
    uint32_t seqA = srv->snd_una;
    tcp_send_at(srv, segB, 200, 300, log_emit, &emit_log);
    tcp_send_at(srv, segC, 200, 300, log_emit, &emit_log);
    /* Three dup ACKs for seqA (= snd_una). */
    emit_log.n = 0;
    ack.ack = seqA;
    tcp_input_at(&stack, &ack, 310, NULL, NULL, log_emit, &emit_log);   /* dup #1 */
    tcp_input_at(&stack, &ack, 311, NULL, NULL, log_emit, &emit_log);   /* dup #2 */
    uint32_t cwnd_pre_fr = srv->cwnd;
    tcp_input_at(&stack, &ack, 312, NULL, NULL, log_emit, &emit_log);   /* dup #3 -> FR */

    /* After fast retransmit: in_recovery, ssthresh = max(flight/2, 2*MSS),
     * cwnd = ssthresh + 3*MSS, oldest segment retransmitted. */
    if (srv->in_recovery == 1
        && srv->ssthresh == TCP_MIN_CWND      /* flight=600 -> half=300 < 2*MSS */
        && srv->cwnd     == TCP_MIN_CWND + 3u * TCP_MSS
        && emit_log.n >= 1
        && emit_log.segs[emit_log.n - 1].seq == seqA
        && emit_log.segs[emit_log.n - 1].payload_len == 200)
         { printf("  PASS: 3 dupacks -> fast retransmit + recovery (cwnd %u -> %u, ssthresh=%u)\n",
                  cwnd_pre_fr, srv->cwnd, srv->ssthresh); g_pass++; }
    else { printf("  FAIL: in_rec=%d cwnd=%u ssthresh=%u emit.n=%d last_seq=%u last_len=%zu\n",
                  srv->in_recovery, srv->cwnd, srv->ssthresh, emit_log.n,
                  emit_log.n ? emit_log.segs[emit_log.n - 1].seq : 0,
                  emit_log.n ? emit_log.segs[emit_log.n - 1].payload_len : (size_t)0);
           g_fail++; }

    /* Recovery exit: cumulative ACK >= recovery_seq deflates cwnd to ssthresh. */
    emit_log.n = 0;
    ack.ack = srv->recovery_seq;
    tcp_input_at(&stack, &ack, 400, NULL, NULL, log_emit, &emit_log);
    if (srv->in_recovery == 0 && srv->cwnd == srv->ssthresh)
         { printf("  PASS: recovery exit deflates cwnd -> ssthresh (%u)\n", srv->cwnd); g_pass++; }
    else { printf("  FAIL: in_rec=%d cwnd=%u ssthresh=%u\n",
                  srv->in_recovery, srv->cwnd, srv->ssthresh); g_fail++; }

    /* RTO timeout collapses cwnd to MSS. */
    srv->cwnd = TCP_INIT_CWND;
    srv->ssthresh = 0xffffffffu;
    srv->rtx_n = 0;
    static const uint8_t segR[400] = {0};
    tcp_send_at(srv, segR, 400, 500, log_emit, &emit_log);
    emit_log.n = 0;
    /* Tick well beyond RTO. */
    tcp_tick(&stack, 500 + TCP_RTO_INIT_MS + 1, log_emit, &emit_log);
    /* ssthresh = max(400/2, 2*MSS) = 2*MSS = 2920; cwnd = MSS = 1460. */
    if (srv->cwnd == TCP_MSS && srv->ssthresh == TCP_MIN_CWND)
         { printf("  PASS: RTO -> cwnd=MSS=%u ssthresh=2*MSS=%u\n",
                  srv->cwnd, srv->ssthresh); g_pass++; }
    else { printf("  FAIL: cwnd=%u ssthresh=%u\n", srv->cwnd, srv->ssthresh); g_fail++; }
}

/* ============================================================== */
/* SHA-256 dispatch — verify scalar and HW path agree on vectors. */
/* ============================================================== */
static void test_sha256_dispatch(void) {
    printf("== SHA-256 dispatch (scalar vs HW) ==\n");

    /* Same input as RFC 6234 §8.5 vector 2. */
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const size_t msg_len = 56;
    const uint8_t expected[32] = {
        0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
        0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
    };

    /* Force the scalar path. */
    sha256_compress_fn_t saved = sha256_compress_fn;
    sha256_compress_fn = sha256_compress_scalar;
    uint8_t scalar_out[32];
    sha256(msg, msg_len, scalar_out);
    check_eq("scalar matches RFC 6234 vec 2", scalar_out, expected, 32);

#if defined(__x86_64__) || defined(__i386__)
    if (cpu_features()->x86_sha && cpu_features()->x86_sse41) {
        sha256_compress_fn = sha256_compress_shani;
        uint8_t hw_out[32];
        sha256(msg, msg_len, hw_out);
        check_eq("sha-ni matches RFC 6234 vec 2", hw_out, expected, 32);

        /* Multi-block stress: 8 blocks of 'a'*64. */
        sha256_ctx c;
        uint8_t blk[64]; memset(blk, 'a', sizeof(blk));
        sha256_compress_fn = sha256_compress_scalar;
        sha256_init(&c);
        for (int i = 0; i < 8; i++) sha256_update(&c, blk, sizeof(blk));
        uint8_t scalar_multi[32]; sha256_final(&c, scalar_multi);

        sha256_compress_fn = sha256_compress_shani;
        sha256_init(&c);
        for (int i = 0; i < 8; i++) sha256_update(&c, blk, sizeof(blk));
        uint8_t hw_multi[32]; sha256_final(&c, hw_multi);
        check_eq("sha-ni 8-block matches scalar", hw_multi, scalar_multi, 32);

        /* Large run-through: 1 MiB of zeros, scalar vs HW. */
        sha256_compress_fn = sha256_compress_scalar;
        sha256_init(&c);
        uint8_t zero[1024]; memset(zero, 0, sizeof(zero));
        for (int i = 0; i < 1024; i++) sha256_update(&c, zero, sizeof(zero));
        uint8_t scalar_big[32]; sha256_final(&c, scalar_big);

        sha256_compress_fn = sha256_compress_shani;
        sha256_init(&c);
        for (int i = 0; i < 1024; i++) sha256_update(&c, zero, sizeof(zero));
        uint8_t hw_big[32]; sha256_final(&c, hw_big);
        check_eq("sha-ni 1MiB-zeros matches scalar", hw_big, scalar_big, 32);
    } else {
        printf("  SKIP: SHA-NI not available on this CPU\n");
    }
#endif

    sha256_compress_fn = saved;
}

/* ============================================================== */
/* Buffer pool — rent/release behaviour, exhaustion, no-alloc path */
/* ============================================================== */
static void test_buffer_pool(void) {
    printf("== Buffer pool ==\n");

    /* 4 slots of 64 bytes each. */
    static uint8_t storage[64 * 4] __attribute__((aligned(8)));
    buffer_pool_t pool;
    int rc = pool_init(&pool, storage, 64, 4);
    if (rc == 0) { printf("  PASS: pool_init succeeded\n"); g_pass++; }
    else         { printf("  FAIL: pool_init rc=%d\n", rc); g_fail++; }

    void* a = pool_rent(&pool);
    void* b = pool_rent(&pool);
    void* c = pool_rent(&pool);
    void* d = pool_rent(&pool);
    void* e = pool_rent(&pool);            /* should fail — exhausted */

    if (a && b && c && d && !e) {
        printf("  PASS: rented 4 slots, 5th returns NULL\n"); g_pass++;
    } else {
        printf("  FAIL: rent sequence wrong: a=%p b=%p c=%p d=%p e=%p\n",
               a, b, c, d, e); g_fail++;
    }

    if (pool.exhaustion_count == 1) {
        printf("  PASS: exhaustion counter == 1\n"); g_pass++;
    } else {
        printf("  FAIL: exhaustion counter = %llu\n",
               (unsigned long long)pool.exhaustion_count); g_fail++;
    }
    if (pool.high_water == 4) {
        printf("  PASS: high water == 4\n"); g_pass++;
    } else {
        printf("  FAIL: high_water = %u\n", pool.high_water); g_fail++;
    }

    /* Release in non-LIFO order; subsequent rents should succeed. */
    pool_release(&pool, b);
    pool_release(&pool, d);
    void* x = pool_rent(&pool);
    void* y = pool_rent(&pool);
    void* z = pool_rent(&pool);            /* exhausted again */

    if (x && y && !z) {
        printf("  PASS: release+rerent works\n"); g_pass++;
    } else {
        printf("  FAIL: x=%p y=%p z=%p\n", x, y, z); g_fail++;
    }

    /* Bounds: returned pointers all sit inside storage. */
    int all_in_range = 1;
    void* slots[] = {a, c, x, y};
    for (size_t i = 0; i < sizeof(slots)/sizeof(slots[0]); i++) {
        uint8_t* p = (uint8_t*)slots[i];
        if (p < storage || p >= storage + sizeof(storage)) all_in_range = 0;
    }
    if (all_in_range) { printf("  PASS: slots within storage bounds\n"); g_pass++; }
    else              { printf("  FAIL: slot out of bounds\n"); g_fail++; }
}

/* ============================================================== */
/* ChaCha20 dispatch — scalar vs SSE2 agreement across lengths.   */
/* ============================================================== */
static void test_chacha20_dispatch(void) {
    printf("== ChaCha20 dispatch (scalar vs SSE2) ==\n");

#if defined(__x86_64__) || defined(__i386__)
    if (!cpu_features()->x86_sse2) {
        printf("  SKIP: SSE2 not available\n");
        return;
    }

    /* Random-looking but deterministic key + nonce. */
    uint8_t key[32], nonce[12];
    for (int i = 0; i < 32; i++) key[i]   = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i * 11 + 5);

    /* Lengths chosen to exercise: <64 (sub-block), 64, 128, 192, 256
     * (exact 4-block boundary), 257 (4-block + 1), 511 (just under
     * 8 blocks), 1024 (16 blocks), 4096 (64 blocks — many SIMD
     * iterations). Plus a counter wrap-ish test at high counter. */
    size_t lens[] = {0, 1, 7, 31, 63, 64, 65, 127, 128, 191, 192,
                     255, 256, 257, 320, 511, 512, 1023, 1024, 4096};
    int all_match = 1;
    for (size_t li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) {
        size_t L = lens[li];
        uint8_t* src     = (uint8_t*)malloc(L + 16);
        uint8_t* out_s   = (uint8_t*)malloc(L + 16);
        uint8_t* out_h   = (uint8_t*)malloc(L + 16);
        for (size_t i = 0; i < L; i++) src[i] = (uint8_t)(i ^ 0x55);

        chacha20_xor_scalar(key, 1, nonce, src, out_s, L);
        chacha20_xor_sse2  (key, 1, nonce, src, out_h, L);
        if (memcmp(out_s, out_h, L) != 0) {
            printf("  FAIL: mismatch at len=%zu\n", L);
            all_match = 0;
        }
        free(src); free(out_s); free(out_h);
    }
    if (all_match) {
        printf("  PASS: scalar == SSE2 across 20 lengths up to 4096\n");
        g_pass++;
    } else {
        g_fail++;
    }

    /* Sanity: SSE2 round-trip (encrypt then decrypt restores plaintext). */
    uint8_t buf[300], orig[300];
    for (size_t i = 0; i < sizeof(buf); i++) orig[i] = buf[i] = (uint8_t)i;
    chacha20_xor_sse2(key, 7, nonce, buf, buf, sizeof(buf));
    chacha20_xor_sse2(key, 7, nonce, buf, buf, sizeof(buf));
    if (memcmp(buf, orig, sizeof(buf)) == 0) {
        printf("  PASS: SSE2 round-trip restores plaintext\n"); g_pass++;
    } else {
        printf("  FAIL: SSE2 round-trip\n"); g_fail++;
    }
#else
    printf("  SKIP: not x86\n");
#endif
}

/* ============================================================== */
/* PEM decoder + cert loader.                                     */
/* ============================================================== */

/* Base64 encoder used ONLY in tests, to construct synthetic PEMs
 * from raw bytes. Production code never needs to encode PEM. */
static const char b64alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static size_t b64_encode_test(const uint8_t* in, size_t in_len,
                              char* out, size_t out_cap) {
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        size_t r = in_len - i;
        uint32_t v = (uint32_t)in[i] << 16;
        if (r > 1) v |= (uint32_t)in[i + 1] << 8;
        if (r > 2) v |= (uint32_t)in[i + 2];
        if (o + 4 > out_cap) return 0;
        out[o++] = b64alpha[(v >> 18) & 0x3F];
        out[o++] = b64alpha[(v >> 12) & 0x3F];
        out[o++] = (r > 1) ? b64alpha[(v >> 6) & 0x3F] : '=';
        out[o++] = (r > 2) ? b64alpha[v & 0x3F]       : '=';
    }
    return o;
}

static void test_pem(void) {
    printf("== PEM decoder ==\n");

    /* Round-trip: encode 32 bytes of known content to PEM, decode,
     * verify equality. */
    uint8_t in[32];
    for (int i = 0; i < 32; i++) in[i] = (uint8_t)(i + 0x10);
    char b64[64]; size_t b64_len = b64_encode_test(in, sizeof(in), b64, sizeof(b64));
    if (b64_len == 0) { printf("  FAIL: b64 encode\n"); g_fail++; return; }

    char pem[256];
    int n = snprintf(pem, sizeof(pem),
                     "-----BEGIN CERTIFICATE-----\n%.*s\n-----END CERTIFICATE-----\n",
                     (int)b64_len, b64);

    uint8_t out[64];
    int dlen = pem_decode(pem, (size_t)n, "CERTIFICATE", out, sizeof(out));
    if (dlen == 32 && memcmp(out, in, 32) == 0) {
        printf("  PASS: 32-byte CERTIFICATE round-trip\n"); g_pass++;
    } else {
        printf("  FAIL: round-trip dlen=%d\n", dlen); g_fail++;
    }

    /* Wrong label rejected. */
    int rc = pem_decode(pem, (size_t)n, "PRIVATE KEY", out, sizeof(out));
    if (rc < 0) { printf("  PASS: label mismatch rejected\n"); g_pass++; }
    else        { printf("  FAIL: label mismatch accepted (%d)\n", rc); g_fail++; }

    /* Truncated body rejected (no END marker). */
    char truncated[256];
    int tn = snprintf(truncated, sizeof(truncated),
                      "-----BEGIN CERTIFICATE-----\n%.*s\n", (int)b64_len, b64);
    rc = pem_decode(truncated, (size_t)tn, "CERTIFICATE", out, sizeof(out));
    if (rc < 0) { printf("  PASS: missing END marker rejected\n"); g_pass++; }
    else        { printf("  FAIL: truncated PEM accepted (%d)\n", rc); g_fail++; }

    /* Chain decode: 2 concatenated CERTIFICATE blocks. */
    char chain_pem[512];
    int cn = snprintf(chain_pem, sizeof(chain_pem),
                      "-----BEGIN CERTIFICATE-----\n%.*s\n-----END CERTIFICATE-----\n"
                      "-----BEGIN CERTIFICATE-----\n%.*s\n-----END CERTIFICATE-----\n",
                      (int)b64_len, b64, (int)b64_len, b64);
    int count = 0;
    int chain_len = pem_decode_chain(chain_pem, (size_t)cn, "CERTIFICATE",
                                     out, sizeof(out), &count);
    if (chain_len == 64 && count == 2) {
        printf("  PASS: chain decode (2x32 = 64 bytes, count=2)\n"); g_pass++;
    } else {
        printf("  FAIL: chain decode len=%d count=%d\n", chain_len, count); g_fail++;
    }
}

/* Build a synthetic minimal-but-valid cert + Ed25519 key PEM in
 * the caller's buffers. The cert is an empty DER SEQUENCE (0x30 0x00)
 * — just enough to satisfy the loader's structural walk. */
static void build_synthetic_cert_pem(char* cert_pem, size_t cert_cap,
                                     char* key_pem,  size_t key_cap) {
    /* Empty SEQUENCE = 0x30 0x00 (2 bytes). */
    uint8_t cert_der[2] = {0x30, 0x00};
    char cb[8];
    size_t cb_len = b64_encode_test(cert_der, 2, cb, sizeof(cb));
    snprintf(cert_pem, cert_cap,
             "-----BEGIN CERTIFICATE-----\n%.*s\n-----END CERTIFICATE-----\n",
             (int)cb_len, cb);

    /* Ed25519 PKCS#8 PrivateKeyInfo:
     *   30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20
     *   <32-byte seed>
     * Total 48 bytes; base64 = 64 chars. */
    uint8_t key_der[48] = {
        0x30, 0x2e, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20
    };
    for (int i = 0; i < 32; i++) key_der[16 + i] = (uint8_t)(0xC0 + i);
    char kb[88];
    size_t kb_len = b64_encode_test(key_der, sizeof(key_der), kb, sizeof(kb));
    snprintf(key_pem, key_cap,
             "-----BEGIN PRIVATE KEY-----\n%.*s\n-----END PRIVATE KEY-----\n",
             (int)kb_len, kb);
}

static void test_cert_store(void) {
    printf("== Cert store (env mode) ==\n");

    char cert_pem[1024], key_pem[1024];
    build_synthetic_cert_pem(cert_pem, sizeof(cert_pem),
                             key_pem,  sizeof(key_pem));

    setenv("PICOWEB_TLS_CERT_PEM", cert_pem, 1);
    setenv("PICOWEB_TLS_KEY_PEM",  key_pem,  1);
    /* Make sure these don't collide. */
    unsetenv("PICOWEB_TLS_CERT_PATH");
    unsetenv("PICOWEB_TLS_KEY_PATH");

    static uint8_t arena[8192];
    cert_store_t store;
    int rc = cert_store_init(&store, arena, sizeof(arena));
    if (rc != 0) { printf("  FAIL: store_init rc=%d\n", rc); g_fail++; return; }

    int loaded = cert_store_load(&store, NULL);
    if (loaded == 1 && store.n_entries == 1) {
        printf("  PASS: env loader added 1 entry\n"); g_pass++;
    } else {
        printf("  FAIL: loaded=%d entries=%d\n", loaded, store.n_entries);
        g_fail++; return;
    }

    /* The default entry should be present and Ed25519. */
    const cert_entry_t* def = cert_store_lookup(&store, NULL, 0);
    if (def && def->key_type == CERT_KEY_ED25519 && def->cert_count == 1) {
        printf("  PASS: default entry is Ed25519, 1 cert in chain\n"); g_pass++;
    } else {
        printf("  FAIL: default lookup: %p type=%d count=%d\n",
               (const void*)def,
               def ? (int)def->key_type : -1,
               def ? def->cert_count : -1);
        g_fail++;
    }

    /* Lookup by random hostname falls back to default. */
    const cert_entry_t* fb = cert_store_lookup(&store, "example.com", 11);
    if (fb == def) {
        printf("  PASS: SNI miss falls back to default\n"); g_pass++;
    } else {
        printf("  FAIL: SNI miss didn't fall back\n"); g_fail++;
    }

    /* Hostname normalization. */
    char h[64] = "Example.COM";
    size_t hl = strlen(h);
    if (cert_normalize_hostname(h, &hl) == 0 &&
        strcmp(h, "example.com") == 0) {
        printf("  PASS: hostname lowercased\n"); g_pass++;
    } else {
        printf("  FAIL: normalize -> '%s'\n", h); g_fail++;
    }

    /* Reject bad chars. */
    char bad[64] = "evil'; DROP TABLE";
    size_t bl = strlen(bad);
    if (cert_normalize_hostname(bad, &bl) != 0) {
        printf("  PASS: bad hostname rejected\n"); g_pass++;
    } else {
        printf("  FAIL: bad hostname accepted\n"); g_fail++;
    }

    /* Ed25519 seed extraction from the synthetic PKCS#8.
     * build_synthetic_cert_pem fills the seed with bytes 0xC0..0xDF;
     * round-trip the PKCS#8 -> 32-byte seed and check. */
    {
        uint8_t seed[32];
        int erc = cert_extract_ed25519_seed(def, seed);
        uint8_t want_seed[32];
        for (int i = 0; i < 32; i++) want_seed[i] = (uint8_t)(0xC0 + i);
        if (erc == 0 && memcmp(seed, want_seed, 32) == 0) {
            printf("  PASS: ed25519 seed extracted from PKCS#8\n"); g_pass++;
        } else {
            printf("  FAIL: seed extract erc=%d\n", erc); g_fail++;
        }
    }

    /* Negative: passing a fake non-Ed25519 entry must return -1. */
    {
        cert_entry_t fake = *def;
        fake.key_type = CERT_KEY_RSA;
        uint8_t seed[32];
        if (cert_extract_ed25519_seed(&fake, seed) < 0) {
            printf("  PASS: non-Ed25519 entry rejected\n"); g_pass++;
        } else {
            printf("  FAIL: non-Ed25519 entry accepted\n"); g_fail++;
        }
    }

    unsetenv("PICOWEB_TLS_CERT_PEM");
    unsetenv("PICOWEB_TLS_KEY_PEM");
}

/* ---------------- TLS 1.3 handshake (parser + builder + secrets) ----- */

/* Helpers for building a synthetic ClientHello on the wire. */
static void w8 (uint8_t** p, uint8_t v)  { (*p)[0] = v; *p += 1; }
static void w16(uint8_t** p, uint16_t v) { (*p)[0] = v >> 8; (*p)[1] = (uint8_t)v; *p += 2; }
static void w24(uint8_t** p, uint32_t v) { (*p)[0] = v >> 16; (*p)[1] = v >> 8; (*p)[2] = (uint8_t)v; *p += 3; }
static void wb (uint8_t** p, const void* s, size_t n) { memcpy(*p, s, n); *p += n; }

static void test_tls13_handshake(void) {
    printf("== TLS 1.3 handshake (CH parse + SH build + secrets) ==\n");

    /* Build a minimal valid ClientHello offering:
     *   - cipher TLS_CHACHA20_POLY1305_SHA256
     *   - SNI: "Example.COM"  (must be lowercased to "example.com")
     *   - supported_versions: 0x0304
     *   - supported_groups: x25519
     *   - key_share: x25519 with a 32-byte pubkey (we compute one)
     */
    uint8_t client_priv[32];
    for (int i = 0; i < 32; i++) client_priv[i] = (uint8_t)(i * 7 + 1);
    /* Clamp per RFC 7748 §5 — x25519() handles internal clamping but
     * the wire pubkey is whatever we send; for the test the value
     * just needs to be 32 bytes the parser accepts. */
    uint8_t client_pub[32];
    x25519(client_pub, client_priv, X25519_BASE_POINT);

    uint8_t buf[2048] = {0};
    uint8_t* p = buf;
    /* Handshake header: type=0x01, len placeholder */
    w8(&p, 0x01);
    uint8_t* hs_len_at = p; w24(&p, 0);
    uint8_t* hs_body = p;

    w16(&p, 0x0303);                                    /* legacy_version */
    for (int i = 0; i < 32; i++) w8(&p, (uint8_t)i);    /* random */
    w8(&p, 0);                                          /* legacy_session_id len */
    /* cipher_suites */
    w16(&p, 2);
    w16(&p, TLS13_CHACHA20_POLY1305_SHA256);
    /* compression_methods */
    w8(&p, 1); w8(&p, 0);

    /* Build extensions block, length backfilled. */
    uint8_t* ext_len_at = p; w16(&p, 0);
    uint8_t* ext_start = p;

    /* SNI: "Example.COM" */
    {
        const char* host = "Example.COM";
        uint16_t host_len = (uint16_t)strlen(host);
        w16(&p, 0x0000);                /* type = server_name */
        w16(&p, 2 + 1 + 2 + host_len);  /* ext_size = list_len(2) + entry */
        w16(&p, 1 + 2 + host_len);      /* server_name_list length */
        w8 (&p, 0);                     /* name_type = host_name */
        w16(&p, host_len);
        wb (&p, host, host_len);
    }
    /* supported_groups: x25519 */
    {
        w16(&p, 0x000a);
        w16(&p, 4);                     /* list_len(2) + 1 group(2) */
        w16(&p, 2);
        w16(&p, TLS13_NAMED_GROUP_X25519);
    }
    /* key_share: x25519 with our pubkey */
    {
        w16(&p, 0x0033);
        w16(&p, 2 + 4 + 32);            /* list_len(2) + entry(4+32) */
        w16(&p, 4 + 32);                /* list_len */
        w16(&p, TLS13_NAMED_GROUP_X25519);
        w16(&p, 32);
        wb (&p, client_pub, 32);
    }
    /* supported_versions: 0x0304 */
    {
        w16(&p, 0x002b);
        w16(&p, 1 + 2);                 /* vlist_len(1) + 1 ver(2) */
        w8 (&p, 2);
        w16(&p, TLS13_SUPPORTED_VERSION);
    }
    /* signature_algorithms: ed25519 (0x0807) */
    {
        w16(&p, 0x000d);
        w16(&p, 2 + 2);                 /* list_len(2) + 1 alg(2) */
        w16(&p, 2);
        w16(&p, TLS13_SIG_SCHEME_ED25519);
    }

    uint16_t ext_len = (uint16_t)(p - ext_start);
    ext_len_at[0] = ext_len >> 8; ext_len_at[1] = (uint8_t)ext_len;
    uint32_t hs_len = (uint32_t)(p - hs_body);
    hs_len_at[0] = (uint8_t)(hs_len >> 16);
    hs_len_at[1] = (uint8_t)(hs_len >> 8);
    hs_len_at[2] = (uint8_t)hs_len;

    size_t ch_total = (size_t)(p - buf);

    tls13_client_hello_t ch;
    int rc = tls13_parse_client_hello(buf, ch_total, &ch);
    if (rc == 0) { printf("  PASS: ClientHello parsed\n"); g_pass++; }
    else         { printf("  FAIL: ClientHello parse rc=%d\n", rc); g_fail++; return; }

    if (ch.offers_chacha_poly && ch.offers_tls13 && ch.offers_x25519 && ch.offers_ed25519)
         { printf("  PASS: client offered chacha/tls13/x25519/ed25519\n"); g_pass++; }
    else { printf("  FAIL: missing offers c=%d v=%d g=%d e=%d\n",
                  ch.offers_chacha_poly, ch.offers_tls13, ch.offers_x25519, ch.offers_ed25519); g_fail++; }

    if (ch.sni_len == 11 && memcmp(ch.sni, "example.com", 11) == 0)
         { printf("  PASS: SNI lowercased to 'example.com'\n"); g_pass++; }
    else { printf("  FAIL: SNI len=%zu '%s'\n", ch.sni_len, ch.sni); g_fail++; }

    if (memcmp(ch.ecdhe_pubkey, client_pub, 32) == 0)
         { printf("  PASS: x25519 key_share extracted\n"); g_pass++; }
    else { printf("  FAIL: x25519 key_share mismatch\n"); g_fail++; }

    /* Build a ServerHello — server picks its own ephemeral keypair. */
    uint8_t server_priv[32];
    for (int i = 0; i < 32; i++) server_priv[i] = (uint8_t)(i * 13 + 7);
    uint8_t server_pub[32];
    x25519(server_pub, server_priv, X25519_BASE_POINT);
    uint8_t server_random[32];
    for (int i = 0; i < 32; i++) server_random[i] = (uint8_t)(0xA0 + i);

    uint8_t sh_buf[256];
    int sh_len = tls13_build_server_hello(sh_buf, sizeof(sh_buf),
                                          server_random, server_pub,
                                          NULL, 0);
    if (sh_len > 0) { printf("  PASS: ServerHello built (%d bytes)\n", sh_len); g_pass++; }
    else            { printf("  FAIL: ServerHello build rc=%d\n", sh_len); g_fail++; return; }

    /* Sanity: SH starts with 0x02 + 24-bit length matching body. */
    if (sh_buf[0] == 0x02) { printf("  PASS: SH handshake type = 0x02\n"); g_pass++; }
    else                   { printf("  FAIL: SH type 0x%02x\n", sh_buf[0]); g_fail++; }
    {
        uint32_t body_len = ((uint32_t)sh_buf[1] << 16) |
                            ((uint32_t)sh_buf[2] << 8)  |
                             (uint32_t)sh_buf[3];
        if ((int)body_len + 4 == sh_len) { printf("  PASS: SH body length matches\n"); g_pass++; }
        else                              { printf("  FAIL: SH body=%u total=%d\n",
                                                  body_len, sh_len); g_fail++; }
    }

    /* Compute handshake secrets. */
    uint8_t shared[32];
    x25519(shared, server_priv, ch.ecdhe_pubkey);
    /* shared on server side must equal X25519(client_priv, server_pub) */
    {
        uint8_t shared_c[32];
        x25519(shared_c, client_priv, server_pub);
        if (memcmp(shared, shared_c, 32) == 0)
             { printf("  PASS: ECDHE shared secret matches both sides\n"); g_pass++; }
        else { printf("  FAIL: ECDHE asymmetric\n"); g_fail++; }
    }

    /* Transcript = SHA-256(CH || SH). */
    uint8_t transcript[32];
    {
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, ch.raw, ch.raw_len);
        sha256_update(&ctx, sh_buf, (size_t)sh_len);
        sha256_final(&ctx, transcript);
    }

    uint8_t hs_secret[32], c_hs[32], s_hs[32];
    int sec_rc = tls13_compute_handshake_secrets(shared, transcript,
                                                 hs_secret, c_hs, s_hs);
    if (sec_rc == 0) { printf("  PASS: handshake secrets derived\n"); g_pass++; }
    else             { printf("  FAIL: handshake secrets rc=%d\n", sec_rc); g_fail++; }

    /* Determinism: re-run with same inputs must produce same outputs. */
    {
        uint8_t hs2[32], c2[32], s2[32];
        tls13_compute_handshake_secrets(shared, transcript, hs2, c2, s2);
        if (memcmp(hs2, hs_secret, 32) == 0 &&
            memcmp(c2, c_hs, 32)      == 0 &&
            memcmp(s2, s_hs, 32)      == 0)
             { printf("  PASS: secrets deterministic\n"); g_pass++; }
        else { printf("  FAIL: secrets non-deterministic\n"); g_fail++; }
    }

    /* c_hs and s_hs must differ. */
    if (memcmp(c_hs, s_hs, 32) != 0)
         { printf("  PASS: c_hs_traffic != s_hs_traffic\n"); g_pass++; }
    else { printf("  FAIL: client/server hs traffic secrets equal\n"); g_fail++; }
}

/* ---------------- scatter-gather (iov) seal ---------------- */

static void test_chacha20_stream_iov(void) {
    printf("== ChaCha20 streaming (fragment-equivalence) ==\n");
    /* Bit-identity: any chunked stream_xor sequence == one-shot xor
     * over the concatenation. Test against a deliberately awkward
     * fragmentation pattern that crosses many 64-byte boundaries. */
    uint8_t key[32];
    uint8_t nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xC0 + i);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x40 + i);

    enum { N = 4096 };
    uint8_t pt[N], ref[N], got[N];
    for (int i = 0; i < N; i++) pt[i] = (uint8_t)(i * 31 + 7);

    chacha20_xor(key, 1, nonce, pt, ref, N);

    /* Fragment sizes intentionally chosen to land mid-block in
     * different ways: 1, 7, 13, 64, 65, 100, 256, ... */
    const size_t frag_sizes[] = {1, 7, 13, 64, 65, 100, 256, 511, 513, 1024, 1003};
    const size_t nf = sizeof(frag_sizes) / sizeof(frag_sizes[0]);

    chacha20_stream_t cs;
    chacha20_stream_init(&cs, key, nonce, 1);
    size_t off = 0, fi = 0;
    while (off < N) {
        size_t take = frag_sizes[fi++ % nf];
        if (off + take > N) take = N - off;
        chacha20_stream_xor(&cs, pt + off, got + off, take);
        off += take;
    }
    if (memcmp(ref, got, N) == 0)
         { printf("  PASS: stream(uneven frags) == one-shot (4096 B)\n"); g_pass++; }
    else { printf("  FAIL: stream != one-shot at first byte that differs\n"); g_fail++; }

    /* Edge: zero-length first fragment must be a no-op. */
    chacha20_stream_init(&cs, key, nonce, 1);
    chacha20_stream_xor(&cs, NULL, NULL, 0);
    chacha20_stream_xor(&cs, pt, got, 200);
    chacha20_xor(key, 1, nonce, pt, ref, 200);
    if (memcmp(ref, got, 200) == 0)
         { printf("  PASS: zero-length frag is no-op\n"); g_pass++; }
    else { printf("  FAIL: zero-length frag corrupted state\n"); g_fail++; }

    /* Edge: 65-byte fragment crossing exactly one block boundary. */
    chacha20_stream_init(&cs, key, nonce, 1);
    chacha20_stream_xor(&cs, pt, got, 65);
    chacha20_xor(key, 1, nonce, pt, ref, 65);
    if (memcmp(ref, got, 65) == 0)
         { printf("  PASS: 65 B single-call matches\n"); g_pass++; }
    else { printf("  FAIL: 65 B single-call mismatch\n"); g_fail++; }
}

static void test_aead_seal_iov(void) {
    printf("== AEAD seal_iov (fragment-equivalence) ==\n");
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[13];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i + 64);
    for (int i = 0; i < 13; i++) aad[i] = (uint8_t)(0x80 | i);

    /* Build a non-trivial plaintext: 3 fragments that are NOT block-
     * aligned individually and total length is not block-aligned. */
    static const uint8_t f0[] = "<!DOCTYPE html><html><head>";
    static const uint8_t f1[] = "<title>picoweb</title></head><body><h1>Hello, ";
    static const uint8_t f2[] = "iov-sealed world!</h1></body></html>";
    pw_iov_t iov[3] = {
        { f0, sizeof(f0) - 1 },
        { f1, sizeof(f1) - 1 },
        { f2, sizeof(f2) - 1 },
    };
    size_t total = pw_iov_total(iov, 3);

    /* Reference: contiguous seal. */
    uint8_t pt[256], ref_ct[256], ref_tag[16];
    size_t off = 0;
    for (unsigned i = 0; i < 3; i++) { memcpy(pt + off, iov[i].base, iov[i].len); off += iov[i].len; }
    aead_chacha20_poly1305_seal(key, nonce, aad, sizeof(aad), pt, total, ref_ct, ref_tag);

    /* Under test: scatter-gather seal. */
    uint8_t got_ct[256], got_tag[16];
    aead_chacha20_poly1305_seal_iov(key, nonce, aad, sizeof(aad),
                                    iov, 3, total, got_ct, got_tag);

    if (memcmp(ref_ct, got_ct, total) == 0)
         { printf("  PASS: ciphertext matches contiguous seal\n"); g_pass++; }
    else { printf("  FAIL: ciphertext differs\n"); g_fail++; }
    if (memcmp(ref_tag, got_tag, 16) == 0)
         { printf("  PASS: tag matches contiguous seal\n"); g_pass++; }
    else { printf("  FAIL: tag differs\n"); g_fail++; }

    /* Round-trip: contiguous open of scatter-sealed ciphertext. */
    uint8_t pt_back[256];
    int rc = aead_chacha20_poly1305_open(key, nonce, aad, sizeof(aad),
                                         got_ct, total, got_tag, pt_back);
    if (rc == 0 && memcmp(pt, pt_back, total) == 0)
         { printf("  PASS: open recovers iov plaintext\n"); g_pass++; }
    else { printf("  FAIL: open(iov-sealed) failed rc=%d\n", rc); g_fail++; }

    /* Edge: zero-fragment chain == empty plaintext. */
    uint8_t empty_tag1[16], empty_tag2[16];
    aead_chacha20_poly1305_seal(key, nonce, aad, sizeof(aad), NULL, 0, NULL, empty_tag1);
    aead_chacha20_poly1305_seal_iov(key, nonce, aad, sizeof(aad),
                                    NULL, 0, 0, NULL, empty_tag2);
    if (memcmp(empty_tag1, empty_tag2, 16) == 0)
         { printf("  PASS: empty-plaintext tag matches\n"); g_pass++; }
    else { printf("  FAIL: empty-plaintext tag differs\n"); g_fail++; }
}

static void test_tls13_record_iov(void) {
    printf("== TLS 1.3 seal_record_iov (fragment-equivalence) ==\n");
    /* Two record_dirs with the same key/iv/seq=0 will produce
     * bit-identical records over equal plaintext. We seal the same
     * bytes once contiguously, once via 3-fragment iov, and compare. */
    tls_record_dir_t a = {0}, b = {0};
    for (int i = 0; i < 32; i++) a.key[i] = b.key[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 12; i++) a.static_iv[i] = b.static_iv[i] = (uint8_t)(0x90 + i);

    static const uint8_t f0[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
    static const uint8_t f1[] = "Content-Length: 42\r\nServer: picoweb\r\n\r\n";
    static const uint8_t f2[] = "<html><body>iov scatter-gather works</body></html>";
    pw_iov_t iov[3] = {
        { f0, sizeof(f0) - 1 },
        { f1, sizeof(f1) - 1 },
        { f2, sizeof(f2) - 1 },
    };
    size_t total = pw_iov_total(iov, 3);

    uint8_t flat[256];
    size_t off = 0;
    for (unsigned i = 0; i < 3; i++) { memcpy(flat + off, iov[i].base, iov[i].len); off += iov[i].len; }

    uint8_t rec_a[512], rec_b[512];
    size_t la = tls13_seal_record(&a, TLS_CT_APPLICATION_DATA, TLS_CT_APPLICATION_DATA,
                                  flat, total, rec_a, sizeof(rec_a));
    size_t lb = tls13_seal_record_iov(&b, TLS_CT_APPLICATION_DATA, TLS_CT_APPLICATION_DATA,
                                      iov, 3, total, rec_b, sizeof(rec_b));

    if (la > 0 && la == lb)
         { printf("  PASS: same wire length (%zu)\n", la); g_pass++; }
    else { printf("  FAIL: wire length la=%zu lb=%zu\n", la, lb); g_fail++; return; }

    if (memcmp(rec_a, rec_b, la) == 0)
         { printf("  PASS: contiguous and iov records are byte-identical\n"); g_pass++; }
    else { printf("  FAIL: records differ\n"); g_fail++; }

    if (a.seq == 1 && b.seq == 1)
         { printf("  PASS: both record_dirs advanced seq to 1\n"); g_pass++; }
    else { printf("  FAIL: seq a=%llu b=%llu\n",
                  (unsigned long long)a.seq, (unsigned long long)b.seq); g_fail++; }

    /* The whole point: round-trip via tls13_open_record. */
    tls_record_dir_t r = {0};
    for (int i = 0; i < 32; i++) r.key[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 12; i++) r.static_iv[i] = (uint8_t)(0x90 + i);
    tls_content_type_t inner = TLS_CT_INVALID;
    uint8_t* pt_out = NULL;
    size_t   pt_len = 0;
    int rc = tls13_open_record(&r, rec_b, lb, &inner, &pt_out, &pt_len);
    if (rc == 0 && inner == TLS_CT_APPLICATION_DATA && pt_len == total &&
        memcmp(pt_out, flat, total) == 0)
         { printf("  PASS: open(iov-sealed) recovers plaintext\n"); g_pass++; }
    else { printf("  FAIL: open rc=%d inner=%d pt_len=%zu/%zu\n",
                  rc, (int)inner, pt_len, total); g_fail++; }
}

/* ---------------- pw_conn run-to-completion ---------------- */

/* Stand-in webserver: looks at the request line, returns a hard-
 * coded HTML response from immutable storage. */
static const uint8_t k_resp_status[]  = "HTTP/1.1 200 OK\r\n";
static const uint8_t k_resp_headers[] = "Content-Type: text/html\r\nContent-Length: 47\r\nConnection: keep-alive\r\nServer: picoweb\r\n\r\n";
static const uint8_t k_resp_chrome_h[]= "<!DOCTYPE html><html><body>";
static const uint8_t k_resp_body[]    = "<h1>iov</h1>";
static const uint8_t k_resp_chrome_f[]= "</body></html>";

static int test_response_fn(const uint8_t* request, size_t request_len,
                            pw_response_t* out, void* user) {
    (void)user;
    /* Sanity: must look like an HTTP request line. */
    if (request_len < 4 || memcmp(request, "GET ", 4) != 0) return -1;
    out->parts[0].base = k_resp_status;   out->parts[0].len = sizeof(k_resp_status)  - 1;
    out->parts[1].base = k_resp_headers;  out->parts[1].len = sizeof(k_resp_headers) - 1;
    out->parts[2].base = k_resp_chrome_h; out->parts[2].len = sizeof(k_resp_chrome_h)- 1;
    out->parts[3].base = k_resp_body;     out->parts[3].len = sizeof(k_resp_body)    - 1;
    out->parts[4].base = k_resp_chrome_f; out->parts[4].len = sizeof(k_resp_chrome_f)- 1;
    out->n = 5;
    out->total_len = pw_iov_total(out->parts, out->n);
    return 0;
}

static void test_pw_conn(void) {
    printf("== pw_conn run-to-completion (RX -> TLS open -> HTTP -> TLS seal -> TX) ==\n");

    /* Two record_dirs that share key/iv: one for the client's TX
     * (== server's RX), one for the server's TX (== client's RX).
     * In a real handshake these come out of derive_traffic_keys. */
    tls_record_dir_t c2s = {0};   /* client -> server */
    tls_record_dir_t s2c = {0};   /* server -> client */
    for (int i = 0; i < 32; i++) c2s.key[i] = (uint8_t)(0xC0 + i);
    for (int i = 0; i < 12; i++) c2s.static_iv[i] = (uint8_t)(0xE0 + i);
    for (int i = 0; i < 32; i++) s2c.key[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 12; i++) s2c.static_iv[i] = (uint8_t)(0x90 + i);

    /* Server connection: rx is c2s, tx is s2c. */
    pw_conn_t server;
    pw_conn_init(&server, &c2s, &s2c);

    /* Client side just uses raw record_dirs to seal/open. */
    tls_record_dir_t client_tx = c2s;
    tls_record_dir_t client_rx = s2c;

    /* --- Client builds a request and seals it. --- */
    static const uint8_t request[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint8_t req_record[512];
    size_t  req_len = tls13_seal_record(&client_tx,
                                        TLS_CT_APPLICATION_DATA,
                                        TLS_CT_APPLICATION_DATA,
                                        request, sizeof(request) - 1,
                                        req_record, sizeof(req_record));
    if (req_len > 0) { printf("  PASS: client sealed request (%zu B)\n", req_len); g_pass++; }
    else             { printf("  FAIL: client seal\n"); g_fail++; return; }

    /* --- Hand the sealed bytes to the server in ONE chunk. --- */
    uint8_t resp_record[1024];
    size_t  resp_len = 0;
    pw_conn_status_t st = pw_conn_rx(&server, req_record, req_len,
                                     test_response_fn, NULL,
                                     resp_record, sizeof(resp_record), &resp_len);
    if (st == PW_CONN_OK)        { printf("  PASS: server processed request (%zu B sealed)\n", resp_len); g_pass++; }
    else                          { printf("  FAIL: server st=%d\n", (int)st); g_fail++; return; }
    if (server.records_in == 1)  { printf("  PASS: server records_in=1\n"); g_pass++; }
    else                          { printf("  FAIL: records_in=%llu\n",
                                          (unsigned long long)server.records_in); g_fail++; }
    if (server.records_out == 1) { printf("  PASS: server records_out=1\n"); g_pass++; }
    else                          { printf("  FAIL: records_out=%llu\n",
                                          (unsigned long long)server.records_out); g_fail++; }

    /* --- Client opens the sealed response and verifies content. --- */
    tls_content_type_t inner = TLS_CT_INVALID;
    uint8_t* pt_out = NULL;
    size_t   pt_len = 0;
    int orc = tls13_open_record(&client_rx, resp_record, resp_len,
                                &inner, &pt_out, &pt_len);
    if (orc == 0 && inner == TLS_CT_APPLICATION_DATA)
         { printf("  PASS: client opened response\n"); g_pass++; }
    else { printf("  FAIL: client open rc=%d inner=%d\n", orc, (int)inner); g_fail++; return; }

    /* Reconstruct expected plaintext = concatenation of fragments. */
    uint8_t expected[256];
    size_t  exp_off = 0;
    memcpy(expected + exp_off, k_resp_status,   sizeof(k_resp_status)   - 1); exp_off += sizeof(k_resp_status)   - 1;
    memcpy(expected + exp_off, k_resp_headers,  sizeof(k_resp_headers)  - 1); exp_off += sizeof(k_resp_headers)  - 1;
    memcpy(expected + exp_off, k_resp_chrome_h, sizeof(k_resp_chrome_h) - 1); exp_off += sizeof(k_resp_chrome_h) - 1;
    memcpy(expected + exp_off, k_resp_body,     sizeof(k_resp_body)     - 1); exp_off += sizeof(k_resp_body)     - 1;
    memcpy(expected + exp_off, k_resp_chrome_f, sizeof(k_resp_chrome_f) - 1); exp_off += sizeof(k_resp_chrome_f) - 1;
    if (pt_len == exp_off && memcmp(pt_out, expected, exp_off) == 0)
         { printf("  PASS: response plaintext matches iov chain\n"); g_pass++; }
    else { printf("  FAIL: pt_len=%zu exp=%zu\n", pt_len, exp_off); g_fail++; }

    /* --- Now exercise NEED_MORE: feed the next request in 3 chunks. --- */
    uint8_t req2_record[512];
    size_t  req2_len = tls13_seal_record(&client_tx,
                                         TLS_CT_APPLICATION_DATA,
                                         TLS_CT_APPLICATION_DATA,
                                         request, sizeof(request) - 1,
                                         req2_record, sizeof(req2_record));
    /* Chunk it: 3 bytes (less than header), then 7 bytes (header complete
     * but body short), then the rest. */
    size_t c1 = 3;
    size_t c2 = 7;
    size_t c3 = req2_len - c1 - c2;

    pw_conn_status_t st1 = pw_conn_rx(&server, req2_record, c1, test_response_fn, NULL,
                                      resp_record, sizeof(resp_record), &resp_len);
    pw_conn_status_t st2 = pw_conn_rx(&server, req2_record + c1, c2, test_response_fn, NULL,
                                      resp_record, sizeof(resp_record), &resp_len);
    pw_conn_status_t st3 = pw_conn_rx(&server, req2_record + c1 + c2, c3, test_response_fn, NULL,
                                      resp_record, sizeof(resp_record), &resp_len);
    if (st1 == PW_CONN_NEED_MORE && st2 == PW_CONN_NEED_MORE && st3 == PW_CONN_OK)
         { printf("  PASS: chunked arrival NEED_MORE,NEED_MORE,OK\n"); g_pass++; }
    else { printf("  FAIL: chunked st1=%d st2=%d st3=%d\n",
                  (int)st1, (int)st2, (int)st3); g_fail++; }
    if (server.records_in == 2)  { printf("  PASS: 2 records processed total\n"); g_pass++; }
    else                          { printf("  FAIL: records_in=%llu\n",
                                          (unsigned long long)server.records_in); g_fail++; }

    /* --- Tampered ciphertext rejected with AUTH_FAIL. --- */
    pw_conn_t s2;
    pw_conn_init(&s2, &c2s, &s2c);
    /* Reset client_tx seq so the next sealed record uses seq 0 (same
     * as the server expects on a fresh connection). */
    client_tx.seq = 0;
    uint8_t bad_record[512];
    size_t bad_len = tls13_seal_record(&client_tx,
                                       TLS_CT_APPLICATION_DATA,
                                       TLS_CT_APPLICATION_DATA,
                                       request, sizeof(request) - 1,
                                       bad_record, sizeof(bad_record));
    bad_record[bad_len - 1] ^= 1;     /* flip the last byte of the tag */
    pw_conn_status_t st_bad = pw_conn_rx(&s2, bad_record, bad_len,
                                         test_response_fn, NULL,
                                         resp_record, sizeof(resp_record), &resp_len);
    if (st_bad == PW_CONN_AUTH_FAIL)
         { printf("  PASS: tampered tag -> AUTH_FAIL\n"); g_pass++; }
    else { printf("  FAIL: tampered st=%d\n", (int)st_bad); g_fail++; }

    /* --- Two valid records concatenated in one pw_conn_rx call must
     *     NOT be merged or dropped. The first call processes ONE
     *     request, leaving the second request buffered in the
     *     engine's RX. A follow-up call (with no new bytes) processes
     *     the second. --- */
    {
        pw_conn_t s3;
        pw_conn_init(&s3, &c2s, &s2c);
        tls_record_dir_t cli_tx2 = c2s; cli_tx2.seq = 0;
        uint8_t recA[512], recB[512];
        size_t  recA_len = tls13_seal_record(&cli_tx2,
                                             TLS_CT_APPLICATION_DATA,
                                             TLS_CT_APPLICATION_DATA,
                                             request, sizeof(request) - 1,
                                             recA, sizeof(recA));
        size_t  recB_len = tls13_seal_record(&cli_tx2,
                                             TLS_CT_APPLICATION_DATA,
                                             TLS_CT_APPLICATION_DATA,
                                             request, sizeof(request) - 1,
                                             recB, sizeof(recB));
        uint8_t both[1024];
        memcpy(both,            recA, recA_len);
        memcpy(both + recA_len, recB, recB_len);

        size_t outlen_1 = 0;
        pw_conn_status_t s_1 = pw_conn_rx(&s3, both, recA_len + recB_len,
                                          test_response_fn, NULL,
                                          resp_record, sizeof(resp_record),
                                          &outlen_1);
        if (s_1 == PW_CONN_OK && outlen_1 > 0 && s3.records_in == 1)
             { printf("  PASS: 1st record of concatenated pair processed\n"); g_pass++; }
        else { printf("  FAIL: concat call1 st=%d records_in=%llu\n",
                      (int)s_1, (unsigned long long)s3.records_in); g_fail++; }

        /* Now drain the second record via a no-bytes call. */
        size_t outlen_2 = 0;
        pw_conn_status_t s_2 = pw_conn_rx(&s3, NULL, 0,
                                          test_response_fn, NULL,
                                          resp_record, sizeof(resp_record),
                                          &outlen_2);
        if (s_2 == PW_CONN_OK && outlen_2 > 0 && s3.records_in == 2)
             { printf("  PASS: 2nd record of concatenated pair processed on follow-up\n"); g_pass++; }
        else { printf("  FAIL: concat call2 st=%d records_in=%llu\n",
                      (int)s_2, (unsigned long long)s3.records_in); g_fail++; }
    }
}

/* ---------------- TLS 1.3 Finished (RFC 8446 §4.4.4) ---------------- */

static void test_tls13_finished(void) {
    printf("== TLS 1.3 Finished (compute + verify + tamper reject) ==\n");

    /* base_key = a hypothetical server_handshake_traffic_secret. */
    uint8_t base_key[32];
    uint8_t transcript[32];
    for (int i = 0; i < 32; i++) base_key[i]   = (uint8_t)(0xB0 + i);
    for (int i = 0; i < 32; i++) transcript[i] = (uint8_t)(0x40 + i);

    uint8_t vd[32];
    int rc = tls13_compute_finished(base_key, transcript, vd);
    if (rc == 0) { printf("  PASS: compute_finished\n"); g_pass++; }
    else         { printf("  FAIL: compute rc=%d\n", rc); g_fail++; return; }

    /* Determinism. */
    {
        uint8_t vd2[32];
        tls13_compute_finished(base_key, transcript, vd2);
        if (memcmp(vd, vd2, 32) == 0)
             { printf("  PASS: deterministic\n"); g_pass++; }
        else { printf("  FAIL: non-deterministic\n"); g_fail++; }
    }

    /* Hand-rolled reference: HMAC(HKDF-Expand-Label(base_key, "finished",
     * "", 32), transcript). Recompute from primitives directly so we
     * also check our keysched plumbing. */
    {
        uint8_t fk[32];
        if (tls13_hkdf_expand_label(base_key, "finished", NULL, 0, fk, 32) != 0) {
            printf("  FAIL: hkdf-expand-label\n"); g_fail++;
        } else {
            uint8_t mac[32];
            hmac_sha256(fk, sizeof(fk), transcript, sizeof(transcript), mac);
            if (memcmp(vd, mac, 32) == 0)
                 { printf("  PASS: matches manual HKDF+HMAC composition\n"); g_pass++; }
            else { printf("  FAIL: differs from HKDF+HMAC reference\n"); g_fail++; }
        }
    }

    /* verify_finished accepts a correct value. */
    if (tls13_verify_finished(base_key, transcript, vd) == 0)
         { printf("  PASS: verify accepts correct verify_data\n"); g_pass++; }
    else { printf("  FAIL: verify rejected correct verify_data\n"); g_fail++; }

    /* Tampered verify_data is rejected. */
    {
        uint8_t bad[32];
        memcpy(bad, vd, 32);
        bad[7] ^= 1;
        if (tls13_verify_finished(base_key, transcript, bad) == -1)
             { printf("  PASS: verify rejects tampered verify_data\n"); g_pass++; }
        else { printf("  FAIL: verify accepted tampered\n"); g_fail++; }
    }

    /* Tampered transcript is rejected. */
    {
        uint8_t tt[32];
        memcpy(tt, transcript, 32);
        tt[15] ^= 0x80;
        if (tls13_verify_finished(base_key, tt, vd) == -1)
             { printf("  PASS: verify rejects mismatching transcript\n"); g_pass++; }
        else { printf("  FAIL: verify accepted mismatching transcript\n"); g_fail++; }
    }

    /* Different traffic secrets MUST produce different verify_data. */
    {
        uint8_t bk2[32];
        memcpy(bk2, base_key, 32);
        bk2[0] ^= 1;
        uint8_t vd2[32];
        tls13_compute_finished(bk2, transcript, vd2);
        if (memcmp(vd, vd2, 32) != 0)
             { printf("  PASS: distinct base_keys -> distinct verify_data\n"); g_pass++; }
        else { printf("  FAIL: collision on different base_key\n"); g_fail++; }
    }
}


/* ---------- TLS 1.3 wire-format builders (EE / Cert / Finished) -------- */

static void test_tls13_build_messages(void) {
    printf("== TLS 1.3 wire builders (EncryptedExtensions / Certificate / Finished) ==\n");

    /* EncryptedExtensions: header (4) + extensions list u16 (=0). 6 bytes. */
    {
        uint8_t buf[16];
        int n = tls13_build_encrypted_extensions(buf, sizeof(buf));
        const uint8_t expect[6] = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
        if (n == 6 && memcmp(buf, expect, 6) == 0)
             { printf("  PASS: EE wire bytes match\n"); g_pass++; }
        else { printf("  FAIL: EE n=%d bytes mismatch\n", n); g_fail++; }

        /* Truncated buffer must be rejected. */
        if (tls13_build_encrypted_extensions(buf, 5) == -1)
             { printf("  PASS: EE rejects undersized buf\n"); g_pass++; }
        else { printf("  FAIL: EE accepted undersized buf\n"); g_fail++; }
    }

    /* Certificate: 1 cert with 4-byte body. Wire layout:
     *   0x0b | u24 body_len
     *   u8 ctx_len = 0
     *   u24 cert_list_len = 3 + 4 + 2 = 9
     *   u24 cert_data_len = 4 | 4 bytes | u16 ext_len = 0
     */
    {
        const uint8_t cert[4] = { 0x30, 0x02, 0x05, 0x00 };  /* fake DER */
        const size_t lens[1] = { 4 };
        uint8_t buf[64];
        int n = tls13_build_certificate(buf, sizeof(buf), cert, lens, 1);
        const uint8_t expect[] = {
            0x0b, 0x00, 0x00, 13,        /* body_len = 1 + 3 + 9 = 13 */
            0x00,                        /* ctx_len  = 0              */
            0x00, 0x00, 9,               /* cert_list_len = 9         */
            0x00, 0x00, 4,               /* cert_data_len = 4         */
            0x30, 0x02, 0x05, 0x00,      /* the cert                  */
            0x00, 0x00                   /* extensions_len = 0        */
        };
        if (n == (int)sizeof(expect) && memcmp(buf, expect, sizeof(expect)) == 0)
             { printf("  PASS: Certificate single-cert wire bytes match\n"); g_pass++; }
        else { printf("  FAIL: Certificate n=%d expected=%zu\n",
                      n, sizeof(expect)); g_fail++; }

        /* Truncated buffer rejected. */
        if (tls13_build_certificate(buf, 5, cert, lens, 1) == -1)
             { printf("  PASS: Certificate rejects undersized buf\n"); g_pass++; }
        else { printf("  FAIL: Certificate accepted undersized buf\n"); g_fail++; }

        /* Two-cert chain. */
        const uint8_t chain[6] = { 0x30, 0x00, 0x30, 0x02, 0x05, 0x00 };
        const size_t lens2[2] = { 2, 4 };
        n = tls13_build_certificate(buf, sizeof(buf), chain, lens2, 2);
        size_t expect_len = 4 + 1 + 3 + (3 + 2 + 2) + (3 + 4 + 2);
        if (n == (int)expect_len && buf[0] == 0x0b && buf[4] == 0x00)
             { printf("  PASS: Certificate two-cert length=%d\n", n); g_pass++; }
        else { printf("  FAIL: Certificate two-cert n=%d want=%zu\n",
                      n, expect_len); g_fail++; }
    }

    /* Finished: header (4) + 32-byte verify_data = 36 bytes. */
    {
        uint8_t vd[32];
        for (int i = 0; i < 32; i++) vd[i] = (uint8_t)(0x10 + i);
        uint8_t buf[64];
        int n = tls13_build_finished(buf, sizeof(buf), vd);
        if (n == 36 && buf[0] == 0x14 && buf[3] == 0x20 &&
            memcmp(buf + 4, vd, 32) == 0)
             { printf("  PASS: Finished wire bytes match\n"); g_pass++; }
        else { printf("  FAIL: Finished n=%d\n", n); g_fail++; }

        if (tls13_build_finished(buf, 35, vd) == -1)
             { printf("  PASS: Finished rejects undersized buf\n"); g_pass++; }
        else { printf("  FAIL: Finished accepted undersized buf\n"); g_fail++; }
    }
}

/* ============================================================== */
/* TLS 1.3 CertificateVerify (RFC 8446 §4.4.3) — Ed25519          */
/* ============================================================== */
static void test_tls13_certificate_verify(void) {
    printf("== TLS 1.3 CertificateVerify (Ed25519) ==\n");

    /* Known transcript hash: bytes 0..31 incrementing (deterministic). */
    uint8_t th[32];
    for (int i = 0; i < 32; i++) th[i] = (uint8_t)i;

    /* ---- Signed-data structure: server label ---- */
    {
        uint8_t sd[TLS13_CV_SIGNED_LEN];
        int rc = tls13_build_certificate_verify_signed_data(sd, th, 1);

        int ok = (rc == 0);
        /* 64 bytes of 0x20 padding. */
        for (int i = 0; i < 64 && ok; i++) if (sd[i] != 0x20) ok = 0;
        /* 33-byte server context label. */
        if (ok && memcmp(sd + 64, "TLS 1.3, server CertificateVerify", 33) != 0) ok = 0;
        /* 0x00 separator. */
        if (ok && sd[97] != 0x00) ok = 0;
        /* Transcript hash. */
        if (ok && memcmp(sd + 98, th, 32) != 0) ok = 0;

        if (ok) { printf("  PASS: signed-data layout (server label)\n"); g_pass++; }
        else    { printf("  FAIL: signed-data layout (server label)\n"); g_fail++; }
    }

    /* ---- Signed-data structure: client label (mTLS path) ---- */
    {
        uint8_t sd[TLS13_CV_SIGNED_LEN];
        int rc = tls13_build_certificate_verify_signed_data(sd, th, 0);
        int ok = (rc == 0) &&
                 memcmp(sd + 64, "TLS 1.3, client CertificateVerify", 33) == 0;
        if (ok) { printf("  PASS: signed-data layout (client label)\n"); g_pass++; }
        else    { printf("  FAIL: signed-data layout (client label)\n"); g_fail++; }
    }

    /* ---- Build full CV wire message + roundtrip-verify the signature ---- */

    /* Use a known seed (RFC 8032 §7.1 TEST 3 seed). */
    uint8_t seed[32];
    unhex("c5aa8df43f9f837bedb7442f31dcb7b1"
          "66d38535076f094b85ce3a2e0b4458f7", seed, 32);
    uint8_t pk[32];
    ed25519_pubkey_from_seed(pk, seed);

    uint8_t cv[72];
    int n = tls13_build_certificate_verify(cv, sizeof(cv), th, seed);

    if (n == 72) { printf("  PASS: CV wire length = 72\n"); g_pass++; }
    else         { printf("  FAIL: CV wire length = %d\n", n); g_fail++; return; }

    /* Header: 0x0f, 0x00, 0x00, 0x44 (body = 4 + 64 = 68). */
    if (cv[0] == 0x0f && cv[1] == 0 && cv[2] == 0 && cv[3] == 68) {
        printf("  PASS: CV handshake header\n"); g_pass++;
    } else {
        printf("  FAIL: CV header bytes %02x %02x %02x %02x\n",
               cv[0], cv[1], cv[2], cv[3]); g_fail++;
    }

    /* SignatureScheme = 0x0807 (ed25519); sig_len = 0x0040 (= 64). */
    if (cv[4] == 0x08 && cv[5] == 0x07 && cv[6] == 0x00 && cv[7] == 0x40) {
        printf("  PASS: CV sig_scheme + sig_len\n"); g_pass++;
    } else {
        printf("  FAIL: CV sig_scheme/len bytes %02x %02x %02x %02x\n",
               cv[4], cv[5], cv[6], cv[7]); g_fail++;
    }

    /* Reconstruct the signed prefix and verify with the extracted sig. */
    uint8_t sd[TLS13_CV_SIGNED_LEN];
    tls13_build_certificate_verify_signed_data(sd, th, 1);

    if (ed25519_verify(cv + 8, sd, TLS13_CV_SIGNED_LEN, pk) == 1) {
        printf("  PASS: CV signature verifies under Ed25519\n"); g_pass++;
    } else {
        printf("  FAIL: CV signature does NOT verify\n"); g_fail++;
    }

    /* ---- Bit-flip in transcript hash must invalidate the signature ---- */
    {
        uint8_t th_bad[32];
        memcpy(th_bad, th, 32);
        th_bad[10] ^= 0x01;
        uint8_t sd_bad[TLS13_CV_SIGNED_LEN];
        tls13_build_certificate_verify_signed_data(sd_bad, th_bad, 1);
        if (ed25519_verify(cv + 8, sd_bad, TLS13_CV_SIGNED_LEN, pk) == 0) {
            printf("  PASS: CV sig fails under altered transcript hash\n"); g_pass++;
        } else {
            printf("  FAIL: CV sig accepted altered transcript hash\n"); g_fail++;
        }
    }

    /* ---- Wrong context (client label) must also fail under server-signed ---- */
    {
        uint8_t sd_wrongctx[TLS13_CV_SIGNED_LEN];
        tls13_build_certificate_verify_signed_data(sd_wrongctx, th, 0);
        if (ed25519_verify(cv + 8, sd_wrongctx, TLS13_CV_SIGNED_LEN, pk) == 0) {
            printf("  PASS: CV sig fails under client context label\n"); g_pass++;
        } else {
            printf("  FAIL: CV sig accepted client context label\n"); g_fail++;
        }
    }

    /* ---- Truncated output buffer rejected. ---- */
    {
        uint8_t small[71];
        if (tls13_build_certificate_verify(small, sizeof(small), th, seed) == -1) {
            printf("  PASS: CV rejects undersized buf (71 bytes)\n"); g_pass++;
        } else {
            printf("  FAIL: CV accepted undersized buf\n"); g_fail++;
        }
    }
}

/* ---------- TLS 1.3 running transcript hash ---------- */

static void test_tls13_transcript(void) {
    printf("== TLS 1.3 transcript hash (running SHA-256) ==\n");

    const uint8_t ch[8] = "ClientHi";   /* not really, but bytes don't care */
    const uint8_t sh[8] = "ServerHi";
    const uint8_t ee[6] = { 0x08, 0x00, 0x00, 0x02, 0x00, 0x00 };

    /* Snapshot after CH+SH must equal SHA-256(CH || SH). */
    tls13_transcript_t t;
    tls13_transcript_init(&t);
    tls13_transcript_update(&t, ch, sizeof(ch));
    tls13_transcript_update(&t, sh, sizeof(sh));
    uint8_t snap1[32];
    tls13_transcript_snapshot(&t, snap1);

    uint8_t reference1[32];
    {
        sha256_ctx s;
        sha256_init(&s);
        sha256_update(&s, ch, sizeof(ch));
        sha256_update(&s, sh, sizeof(sh));
        sha256_final(&s, reference1);
    }
    if (memcmp(snap1, reference1, 32) == 0)
         { printf("  PASS: snapshot1 matches SHA-256(CH||SH)\n"); g_pass++; }
    else { printf("  FAIL: snapshot1 mismatch\n"); g_fail++; }

    /* Snapshot is non-destructive: continue, snapshot again, compare. */
    tls13_transcript_update(&t, ee, sizeof(ee));
    uint8_t snap2[32];
    tls13_transcript_snapshot(&t, snap2);

    uint8_t reference2[32];
    {
        sha256_ctx s;
        sha256_init(&s);
        sha256_update(&s, ch, sizeof(ch));
        sha256_update(&s, sh, sizeof(sh));
        sha256_update(&s, ee, sizeof(ee));
        sha256_final(&s, reference2);
    }
    if (memcmp(snap2, reference2, 32) == 0)
         { printf("  PASS: snapshot2 matches SHA-256(CH||SH||EE) (non-destructive)\n"); g_pass++; }
    else { printf("  FAIL: snapshot2 mismatch — was snapshot destructive?\n"); g_fail++; }

    /* Two snapshots in a row return identical bytes. */
    uint8_t snap2b[32];
    tls13_transcript_snapshot(&t, snap2b);
    if (memcmp(snap2, snap2b, 32) == 0)
         { printf("  PASS: repeat snapshot is idempotent\n"); g_pass++; }
    else { printf("  FAIL: repeat snapshot drifted\n"); g_fail++; }
}

/* ====================================================================
 * Port pre-jump table (dispatch + TCP integration)
 * ==================================================================== */

/* --- Stub services for the dispatch tests ---------------------------- */

typedef struct {
    uint8_t in_use;
    uint8_t reply[64];
    size_t  reply_len;
    uint32_t remote_ip;
    uint16_t remote_port;
} echo_slot_t;

typedef struct {
    /* Per-conn pool with 2 slots so we can test exhaustion. */
    echo_slot_t slots[2];
    int       opened;     /* counters */
    int       closed;
    int       data_calls;
    /* Behavioural switches set by the test before exercising the svc. */
    pw_disp_status_t next_status;
    int       refuse_next_open;     /* if 1, on_open returns NULL once    */
    uint8_t*  next_reply_bytes;
    size_t    next_reply_len;
} echo_svc_t;

static void echo_svc_reset(echo_svc_t* s) {
    memset(s, 0, sizeof(*s));
    s->next_status = PW_DISP_NO_OUTPUT;
}

static void* echo_on_open(void* svc_state, const pw_conn_info_t* info) {
    echo_svc_t* s = svc_state;
    if (s->refuse_next_open) { s->refuse_next_open = 0; return NULL; }
    for (unsigned i = 0; i < sizeof(s->slots)/sizeof(s->slots[0]); i++) {
        if (!s->slots[i].in_use) {
            s->slots[i].in_use      = 1;
            s->slots[i].remote_ip   = info->remote_ip;
            s->slots[i].remote_port = info->remote_port;
            s->slots[i].reply_len   = 0;
            s->opened++;
            return &s->slots[i];
        }
    }
    return NULL;   /* pool exhausted -> RST */
}

static pw_disp_status_t echo_on_data(void* per_conn_state,
                                     const uint8_t* data, size_t len,
                                     pw_iov_t* iov_out, unsigned iov_max,
                                     unsigned* iov_n) {
    (void)data; (void)len; (void)iov_max;
    /* Find the parent svc via the slot pointer trick: tests stash the
     * shared svc in a global so the callback can read its switches. */
    extern echo_svc_t* g_active_echo;
    echo_svc_t* svc = g_active_echo;
    svc->data_calls++;

    *iov_n = 0;
    if (svc->next_status == PW_DISP_OUTPUT ||
        svc->next_status == PW_DISP_OUTPUT_AND_CLOSE) {
        if (svc->next_reply_bytes && svc->next_reply_len) {
            iov_out[0].base = svc->next_reply_bytes;
            iov_out[0].len  = svc->next_reply_len;
            *iov_n = 1;
        }
    }
    /* Note per_conn_state is one of the slot structs - prove the
     * pointer was threaded through correctly. */
    if ((uintptr_t)per_conn_state < (uintptr_t)svc ||
        (uintptr_t)per_conn_state >= (uintptr_t)svc + sizeof(*svc)) {
        /* Bad: per_conn_state is not within svc->slots. */
        return PW_DISP_ERROR;
    }
    return svc->next_status;
}

static void echo_on_close(void* per_conn_state) {
    /* Mark the slot free. */
    echo_slot_t* slot = per_conn_state;
    slot->in_use = 0;
    extern echo_svc_t* g_active_echo;
    if (g_active_echo) g_active_echo->closed++;
}

echo_svc_t* g_active_echo = NULL;

/* ---------- dispatch_table: register / lookup / dup / cap -------- */

static void test_dispatch_table(void) {
    printf("== Dispatch table (register / lookup / dup / cap) ==\n");

    pw_dispatch_t d;
    pw_dispatch_init(&d);

    pw_service_t s1 = {
        .proto = PW_PROTO_TCP, .port = 443,
        .svc_state = (void*)0xAA, .on_data = echo_on_data,
    };
    pw_service_t s2 = {
        .proto = PW_PROTO_TCP, .port = 80,
        .svc_state = (void*)0xBB, .on_data = echo_on_data,
    };
    pw_service_t s3_udp = {
        .proto = PW_PROTO_UDP, .port = 443,            /* same port, different proto */
        .svc_state = (void*)0xCC, .on_data = echo_on_data,
    };
    pw_service_t s_dup = {
        .proto = PW_PROTO_TCP, .port = 443,            /* duplicate of s1 */
        .svc_state = (void*)0xDD, .on_data = echo_on_data,
    };
    pw_service_t s_no_data = {                          /* missing on_data */
        .proto = PW_PROTO_TCP, .port = 81, .on_data = NULL,
    };
    pw_service_t s_zero_port = {
        .proto = PW_PROTO_TCP, .port = 0, .on_data = echo_on_data,
    };

    if (pw_dispatch_register(&d, &s1) == 0)
         { printf("  PASS: register tcp/443\n"); g_pass++; }
    else { printf("  FAIL: register tcp/443\n"); g_fail++; }

    if (pw_dispatch_register(&d, &s2) == 0)
         { printf("  PASS: register tcp/80\n"); g_pass++; }
    else { printf("  FAIL: register tcp/80\n"); g_fail++; }

    if (pw_dispatch_register(&d, &s3_udp) == 0)
         { printf("  PASS: register udp/443 (different proto, same port)\n"); g_pass++; }
    else { printf("  FAIL: register udp/443\n"); g_fail++; }

    if (pw_dispatch_register(&d, &s_dup) == -1)
         { printf("  PASS: duplicate tcp/443 rejected\n"); g_pass++; }
    else { printf("  FAIL: duplicate tcp/443 accepted\n"); g_fail++; }

    if (pw_dispatch_register(&d, &s_no_data) == -1)
         { printf("  PASS: missing on_data rejected\n"); g_pass++; }
    else { printf("  FAIL: missing on_data accepted\n"); g_fail++; }

    if (pw_dispatch_register(&d, &s_zero_port) == -1)
         { printf("  PASS: port=0 rejected\n"); g_pass++; }
    else { printf("  FAIL: port=0 accepted\n"); g_fail++; }

    /* Lookup hits */
    const pw_service_t* g = pw_dispatch_lookup(&d, PW_PROTO_TCP, 443);
    if (g && g->svc_state == (void*)0xAA)
         { printf("  PASS: lookup tcp/443 -> s1\n"); g_pass++; }
    else { printf("  FAIL: lookup tcp/443\n"); g_fail++; }

    g = pw_dispatch_lookup(&d, PW_PROTO_UDP, 443);
    if (g && g->svc_state == (void*)0xCC)
         { printf("  PASS: lookup udp/443 -> s3_udp\n"); g_pass++; }
    else { printf("  FAIL: lookup udp/443\n"); g_fail++; }

    if (pw_dispatch_lookup(&d, PW_PROTO_TCP, 999) == NULL)
         { printf("  PASS: lookup miss -> NULL\n"); g_pass++; }
    else { printf("  FAIL: lookup miss returned non-NULL\n"); g_fail++; }

    /* Cap: fill the table to PW_DISPATCH_MAX. We've used 3 slots so
     * we add (PW_DISPATCH_MAX - 3) more, then the next must fail. */
    int added = 0;
    for (uint16_t p = 1000; p < 1000 + PW_DISPATCH_MAX; p++) {
        pw_service_t s = {
            .proto = PW_PROTO_TCP, .port = p,
            .svc_state = (void*)(uintptr_t)p, .on_data = echo_on_data,
        };
        if (pw_dispatch_register(&d, &s) == 0) added++;
        else break;
    }
    if (added == PW_DISPATCH_MAX - 3)
         { printf("  PASS: filled to cap (%d entries added)\n", added); g_pass++; }
    else { printf("  FAIL: cap miscount added=%d expected=%d\n",
                  added, PW_DISPATCH_MAX - 3); g_fail++; }

    pw_service_t over = {
        .proto = PW_PROTO_TCP, .port = 9999,
        .svc_state = (void*)1, .on_data = echo_on_data,
    };
    if (pw_dispatch_register(&d, &over) == -1)
         { printf("  PASS: register past cap rejected\n"); g_pass++; }
    else { printf("  FAIL: register past cap accepted\n"); g_fail++; }
}

/* ---------- tcp_dispatch: full lifecycle through dispatch path ---- */

static void test_tcp_dispatch(void) {
    printf("== TCP + dispatch (multi-service, lifecycle, on_open at ESTABLISHED) ==\n");

    /* Two services: tls-ish on 443, http-ish on 80. */
    echo_svc_t svc443; echo_svc_reset(&svc443);
    echo_svc_t svc80;  echo_svc_reset(&svc80);

    pw_service_t s443 = {
        .proto = PW_PROTO_TCP, .port = 443,
        .svc_state = &svc443,
        .on_open = echo_on_open, .on_data = echo_on_data, .on_close = echo_on_close,
    };
    pw_service_t s80 = {
        .proto = PW_PROTO_TCP, .port = 80,
        .svc_state = &svc80,
        .on_open = echo_on_open, .on_data = echo_on_data, .on_close = echo_on_close,
    };
    pw_dispatch_t disp; pw_dispatch_init(&disp);
    pw_dispatch_register(&disp, &s443);
    pw_dispatch_register(&disp, &s80);

    tcp_stack_t stack;
    tcp_attach_dispatch(&stack, 0x0a000002u, &disp);

    emit_log_t log = {0};

    /* (1) SYN to UNKNOWN port -> RST, no service touched. */
    {
        tcp_seg_t syn = {0};
        syn.src_ip=0x0a000001u; syn.dst_ip=0x0a000002u;
        syn.src_port=5555;     syn.dst_port=999;
        syn.seq=100; syn.flags=TCPF_SYN; syn.window=65535;
        log.n = 0;
        tcp_input(&stack, &syn, NULL, NULL, log_emit, &log);
        if (log.n == 1 && (log.segs[0].flags & TCPF_RST))
             { printf("  PASS: unknown port -> RST\n"); g_pass++; }
        else { printf("  FAIL: unknown port n=%d flags=0x%02x\n",
                      log.n, log.n?log.segs[0].flags:0); g_fail++; }
        if (svc443.opened == 0 && svc80.opened == 0)
             { printf("  PASS: no service on_open fired\n"); g_pass++; }
        else { printf("  FAIL: phantom on_open\n"); g_fail++; }
    }

    /* (2) Full handshake on port 443.
     * Critical assertion: on_open fires at ESTABLISHED, NOT at SYN. */
    g_active_echo = &svc443;
    uint32_t srv_iss;
    {
        log.n = 0;
        tcp_seg_t syn = {0};
        syn.src_ip=0x0a000001u; syn.dst_ip=0x0a000002u;
        syn.src_port=4242;     syn.dst_port=443;
        syn.seq=1000; syn.flags=TCPF_SYN; syn.window=65535;
        tcp_input(&stack, &syn, NULL, NULL, log_emit, &log);
        if (log.n==1 && (log.segs[0].flags & (TCPF_SYN|TCPF_ACK))==(TCPF_SYN|TCPF_ACK))
             { printf("  PASS: SYN -> SYN+ACK on 443\n"); g_pass++; }
        else { printf("  FAIL: 443 SYN+ACK n=%d\n", log.n); g_fail++; }
        srv_iss = log.segs[0].seq;

        if (svc443.opened == 0)
             { printf("  PASS: on_open NOT fired at SYN_RECEIVED (SYN-flood-safe)\n"); g_pass++; }
        else { printf("  FAIL: on_open fired too early (opened=%d)\n", svc443.opened); g_fail++; }
    }
    {
        /* Final ACK -> ESTABLISHED -> on_open fires NOW. */
        log.n = 0;
        tcp_seg_t ack = {0};
        ack.src_ip=0x0a000001u; ack.dst_ip=0x0a000002u;
        ack.src_port=4242;     ack.dst_port=443;
        ack.seq=1001; ack.ack=srv_iss+1;
        ack.flags=TCPF_ACK; ack.window=65535;
        tcp_input(&stack, &ack, NULL, NULL, log_emit, &log);
        if (svc443.opened == 1 && svc443.closed == 0)
             { printf("  PASS: on_open fired at ESTABLISHED (opened=1 closed=0)\n"); g_pass++; }
        else { printf("  FAIL: open/close = %d/%d\n", svc443.opened, svc443.closed); g_fail++; }
    }

    /* (3) Send data, service returns OUTPUT - bytes flow back. */
    {
        log.n = 0;
        const char* req = "ping";
        uint8_t reply[] = "pong";
        svc443.next_reply_bytes = reply;
        svc443.next_reply_len   = 4;
        svc443.next_status      = PW_DISP_OUTPUT;

        tcp_seg_t pkt = {0};
        pkt.src_ip=0x0a000001u; pkt.dst_ip=0x0a000002u;
        pkt.src_port=4242;     pkt.dst_port=443;
        pkt.seq=1001; pkt.ack=srv_iss+1;
        pkt.flags=TCPF_ACK|TCPF_PSH; pkt.window=65535;
        pkt.payload=(const uint8_t*)req;
        pkt.payload_len=4;
        tcp_input(&stack, &pkt, NULL, NULL, log_emit, &log);

        /* Expect: 1 ACK + 1 data segment carrying "pong" */
        int saw_data = 0;
        for (int i = 0; i < log.n; i++) {
            if (log.segs[i].payload_len == 4 &&
                memcmp(log.segs[i].payload, "pong", 4) == 0) saw_data = 1;
        }
        if (svc443.data_calls == 1 && saw_data)
             { printf("  PASS: OUTPUT path delivered service reply\n"); g_pass++; }
        else { printf("  FAIL: OUTPUT calls=%d saw_data=%d log.n=%d\n",
                      svc443.data_calls, saw_data, log.n); g_fail++; }
    }

    /* (4) Send data, service returns OUTPUT_AND_CLOSE - bytes + FIN. */
    {
        log.n = 0;
        uint8_t reply[] = "bye";
        svc443.next_reply_bytes = reply;
        svc443.next_reply_len   = 3;
        svc443.next_status      = PW_DISP_OUTPUT_AND_CLOSE;

        tcp_seg_t pkt = {0};
        pkt.src_ip=0x0a000001u; pkt.dst_ip=0x0a000002u;
        pkt.src_port=4242;     pkt.dst_port=443;
        pkt.seq=1005; pkt.ack=srv_iss+1;   /* 1001+4 from prev request */
        pkt.flags=TCPF_ACK|TCPF_PSH; pkt.window=65535;
        pkt.payload=(const uint8_t*)"x";
        pkt.payload_len=1;
        tcp_input(&stack, &pkt, NULL, NULL, log_emit, &log);

        int saw_fin = 0, saw_data = 0;
        for (int i = 0; i < log.n; i++) {
            if (log.segs[i].flags & TCPF_FIN) saw_fin = 1;
            if (log.segs[i].payload_len == 3 &&
                memcmp(log.segs[i].payload, "bye", 3) == 0) saw_data = 1;
        }
        if (saw_data && saw_fin)
             { printf("  PASS: OUTPUT_AND_CLOSE -> data + FIN\n"); g_pass++; }
        else { printf("  FAIL: data=%d fin=%d\n", saw_data, saw_fin); g_fail++; }
    }

    /* (5) Closing client ACK to LAST_ACK -> on_close fires exactly once. */
    {
        log.n = 0;
        tcp_conn_t* c = NULL;
        for (unsigned i = 0; i < TCP_TABLE_SIZE; i++) {
            if (stack.conns[i].state == TCP_LAST_ACK) { c = &stack.conns[i]; break; }
        }
        if (!c) {
            printf("  FAIL: no LAST_ACK conn after OUTPUT_AND_CLOSE\n"); g_fail++;
        } else {
            tcp_seg_t fa = {0};
            fa.src_ip=0x0a000001u; fa.dst_ip=0x0a000002u;
            fa.src_port=4242;     fa.dst_port=443;
            fa.seq=1006; fa.ack=c->snd_nxt;
            fa.flags=TCPF_ACK; fa.window=65535;
            int closed_before = svc443.closed;
            tcp_input(&stack, &fa, NULL, NULL, log_emit, &log);
            int closed_after = svc443.closed;
            if (closed_after == closed_before + 1 && c->state == TCP_CLOSED)
                 { printf("  PASS: on_close fired exactly once (closed %d->%d)\n",
                          closed_before, closed_after); g_pass++; }
            else { printf("  FAIL: closed %d->%d state=%d\n",
                          closed_before, closed_after, c->state); g_fail++; }
        }
    }

    /* (6) Pool exhaustion: open 2 conns (to fill 2-slot pool), then 3rd
     * is refused -> on_open returns NULL -> RST + no on_close fired. */
    echo_svc_reset(&svc443);
    g_active_echo = &svc443;
    /* Need to also reset the TCP stack's connection table state so we
     * have fresh slots after the previous CLOSED conns. */
    for (unsigned i = 0; i < TCP_TABLE_SIZE; i++) stack.conns[i].state = TCP_CLOSED;
    {
        for (int n = 0; n < 3; n++) {
            tcp_seg_t syn = {0};
            syn.src_ip=0x0a00000au + n; syn.dst_ip=0x0a000002u;
            syn.src_port=6000+n;       syn.dst_port=443;
            syn.seq=2000; syn.flags=TCPF_SYN; syn.window=65535;
            log.n = 0;
            tcp_input(&stack, &syn, NULL, NULL, log_emit, &log);
            uint32_t iss = log.segs[0].seq;

            tcp_seg_t ack = {0};
            ack.src_ip=0x0a00000au + n; ack.dst_ip=0x0a000002u;
            ack.src_port=6000+n;       ack.dst_port=443;
            ack.seq=2001; ack.ack=iss+1;
            ack.flags=TCPF_ACK; ack.window=65535;
            log.n = 0;
            tcp_input(&stack, &ack, NULL, NULL, log_emit, &log);
            /* On the 3rd, expect RST in the emit log. */
            if (n == 2) {
                int saw_rst = 0;
                for (int i = 0; i < log.n; i++)
                    if (log.segs[i].flags & TCPF_RST) saw_rst = 1;
                if (saw_rst)
                     { printf("  PASS: 3rd conn -> RST (pool exhausted)\n"); g_pass++; }
                else { printf("  FAIL: 3rd conn no RST n=%d\n", log.n); g_fail++; }
            }
        }
        if (svc443.opened == 2 && svc443.closed == 0)
             { printf("  PASS: only 2 successful on_opens, 0 on_closes (refused not closed)\n"); g_pass++; }
        else { printf("  FAIL: opened=%d closed=%d\n", svc443.opened, svc443.closed); g_fail++; }
    }

    /* (7) tcp_sendv with 2-fragment iov coalesces correctly. */
    {
        /* Find any one of the still-ESTABLISHED conns from (6). */
        tcp_conn_t* c = NULL;
        for (unsigned i = 0; i < TCP_TABLE_SIZE; i++) {
            if (stack.conns[i].state == TCP_ESTABLISHED) { c = &stack.conns[i]; break; }
        }
        if (!c) { printf("  FAIL: no ESTABLISHED conn for sendv test\n"); g_fail++; }
        else {
            log.n = 0;
            const uint8_t a[] = "hello-";
            const uint8_t b[] = "world";
            pw_iov_t iov[2] = {
                { .base = a, .len = sizeof(a)-1 },
                { .base = b, .len = sizeof(b)-1 },
            };
            int rc = tcp_sendv(c, iov, 2, log_emit, &log);
            const char* expect = "hello-world";
            size_t elen = strlen(expect);
            if (rc == (int)elen && log.n == 1 &&
                log.segs[0].payload_len == elen &&
                memcmp(log.segs[0].payload, expect, elen) == 0)
                 { printf("  PASS: tcp_sendv 2-fragment coalesce (%zu B)\n", elen); g_pass++; }
            else { printf("  FAIL: sendv rc=%d log.n=%d plen=%zu\n",
                          rc, log.n, log.n?log.segs[0].payload_len:0); g_fail++; }
        }
    }

    /* (8) Routing: data to port 80 hits svc80, not svc443. */
    g_active_echo = &svc80;
    /* Reset the TCP table so we can open a fresh conn on port 80. */
    for (unsigned i = 0; i < TCP_TABLE_SIZE; i++) stack.conns[i].state = TCP_CLOSED;
    {
        tcp_seg_t syn = {0};
        syn.src_ip=0x0a00000bu; syn.dst_ip=0x0a000002u;
        syn.src_port=7777;     syn.dst_port=80;
        syn.seq=4000; syn.flags=TCPF_SYN; syn.window=65535;
        log.n = 0;
        tcp_input(&stack, &syn, NULL, NULL, log_emit, &log);
        uint32_t iss = log.segs[0].seq;

        tcp_seg_t ack = {0};
        ack.src_ip=0x0a00000bu; ack.dst_ip=0x0a000002u;
        ack.src_port=7777;     ack.dst_port=80;
        ack.seq=4001; ack.ack=iss+1;
        ack.flags=TCPF_ACK; ack.window=65535;
        log.n = 0;
        int prev_443 = svc443.opened;
        int prev_80  = svc80.opened;
        tcp_input(&stack, &ack, NULL, NULL, log_emit, &log);
        if (svc80.opened == prev_80 + 1 && svc443.opened == prev_443)
             { printf("  PASS: port 80 conn routed to svc80 (svc443 untouched)\n"); g_pass++; }
        else { printf("  FAIL: 80 routed wrong (svc443=%d svc80=%d)\n",
                      svc443.opened, svc80.opened); g_fail++; }
    }

    g_active_echo = NULL;
}

/* ====================================================================
 * BearSSL-style TLS engine (post-handshake app-data path)
 * ==================================================================== */

/* Helper: install symmetric app keys on two engines so they can
 * encrypt/decrypt for each other. Returns 0 on success. */
static int test_install_symmetric_keys(pw_tls_engine_t* server,
                                       pw_tls_engine_t* client) {
    uint8_t ck[32], civ[12], sk[32], siv[12];
    for (int i = 0; i < 32; i++) ck[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 12; i++) civ[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 32; i++) sk[i] = (uint8_t)(0x80 + i);
    for (int i = 0; i < 12; i++) siv[i] = (uint8_t)(0xa0 + i);
    if (pw_tls_engine_install_app_keys(server, ck, civ, sk, siv, 1) != 0) return -1;
    if (pw_tls_engine_install_app_keys(client, ck, civ, sk, siv, 0) != 0) return -1;
    return 0;
}

static void test_tls_engine(void) {
    printf("== BearSSL-style TLS engine (RX/TX/APP_IN/APP_OUT ports) ==\n");

    /* Engines are large (~66KB each) - allocate on heap to avoid
     * blowing the test runner's stack frame. */
    pw_tls_engine_t* svr = malloc(sizeof(*svr));
    pw_tls_engine_t* cli = malloc(sizeof(*cli));
    if (!svr || !cli) {
        printf("  FAIL: engine alloc\n"); g_fail++; free(svr); free(cli); return;
    }
    pw_tls_engine_init(svr);
    pw_tls_engine_init(cli);

    /* Pre-install: state must be HANDSHAKE, no want bits set for app. */
    if (pw_tls_state(svr) == PW_TLS_ST_HANDSHAKE)
         { printf("  PASS: fresh engine in HANDSHAKE state\n"); g_pass++; }
    else { printf("  FAIL: state=%d\n", pw_tls_state(svr)); g_fail++; }

    if ((pw_tls_want(svr) & PW_TLS_APP_OUT_OK) == 0)
         { printf("  PASS: APP_OUT_OK NOT set in HANDSHAKE state\n"); g_pass++; }
    else { printf("  FAIL: APP_OUT_OK leaked through HANDSHAKE\n"); g_fail++; }

    /* app_out_push must refuse before keys are installed. */
    {
        pw_iov_t iov = { .base = (const uint8_t*)"x", .len = 1 };
        if (pw_tls_app_out_push(svr, &iov, 1) == -1)
             { printf("  PASS: app_out_push refused before keys\n"); g_pass++; }
        else { printf("  FAIL: app_out_push accepted before keys\n"); g_fail++; }
    }

    if (test_install_symmetric_keys(svr, cli) == 0)
         { printf("  PASS: install symmetric app keys\n"); g_pass++; }
    else { printf("  FAIL: install keys\n"); g_fail++; goto out; }

    if (pw_tls_state(svr) == PW_TLS_ST_APP && pw_tls_state(cli) == PW_TLS_ST_APP)
         { printf("  PASS: state -> APP after key install\n"); g_pass++; }
    else { printf("  FAIL: state svr=%d cli=%d\n",
                  pw_tls_state(svr), pw_tls_state(cli)); g_fail++; }

    /* Want bits in APP state with empty buffers:
     *   WANT_RX (room for cipher), APP_OUT_OK (room for plaintext)
     *   NOT WANT_TX (no cipher to send), NOT APP_IN_RDY (no plaintext) */
    {
        unsigned w = pw_tls_want(svr);
        int ok = (w & PW_TLS_WANT_RX) && (w & PW_TLS_APP_OUT_OK) &&
                 !(w & PW_TLS_WANT_TX) && !(w & PW_TLS_APP_IN_RDY);
        if (ok) { printf("  PASS: want bits in fresh APP state\n"); g_pass++; }
        else    { printf("  FAIL: want=0x%x\n", w); g_fail++; }
    }

    /* ---------- Round-trip 1: client -> server -> response ---------- */

    /* Client pushes plaintext request, steps. */
    const char* req = "GET / HTTP/1.1\r\nHost: api\r\n\r\n";
    size_t req_len = strlen(req);
    {
        pw_iov_t iov = { .base = (const uint8_t*)req, .len = req_len };
        if (pw_tls_app_out_push(cli, &iov, 1) == 0)
             { printf("  PASS: client app_out_push request (%zu B)\n", req_len); g_pass++; }
        else { printf("  FAIL: client push\n"); g_fail++; goto out; }
    }
    pw_tls_step(cli);

    /* Client TX should now hold a sealed record. */
    size_t cli_tx_len;
    const uint8_t* cli_tx = pw_tls_tx_buf(cli, &cli_tx_len);
    if (cli_tx_len == TLS13_RECORD_HEADER_LEN + req_len + 1 + TLS13_AEAD_TAG_LEN)
         { printf("  PASS: client TX has sealed record (%zu B)\n", cli_tx_len); g_pass++; }
    else { printf("  FAIL: client tx_len=%zu\n", cli_tx_len); g_fail++; goto out; }

    /* Pump bytes: client TX -> server RX. */
    {
        size_t cap;
        uint8_t* dst = pw_tls_rx_buf(svr, &cap);
        if (cli_tx_len > cap) { printf("  FAIL: server RX too small\n"); g_fail++; goto out; }
        memcpy(dst, cli_tx, cli_tx_len);
        pw_tls_rx_ack(svr, cli_tx_len);
        pw_tls_tx_ack(cli, cli_tx_len);
    }

    /* Server steps - record opens into APP_IN. */
    pw_tls_step(svr);
    {
        size_t pt_len;
        const uint8_t* pt = pw_tls_app_in_buf(svr, &pt_len);
        if (pt_len == req_len && memcmp(pt, req, req_len) == 0)
             { printf("  PASS: server APP_IN matches client plaintext\n"); g_pass++; }
        else { printf("  FAIL: server pt_len=%zu vs %zu\n", pt_len, req_len); g_fail++; goto out; }
        if ((pw_tls_want(svr) & PW_TLS_APP_IN_RDY))
             { printf("  PASS: APP_IN_RDY want bit set\n"); g_pass++; }
        else { printf("  FAIL: APP_IN_RDY missing\n"); g_fail++; }
        pw_tls_app_in_ack(svr, pt_len);
    }
    if ((pw_tls_want(svr) & PW_TLS_APP_IN_RDY) == 0)
         { printf("  PASS: APP_IN_RDY clears after ack\n"); g_pass++; }
    else { printf("  FAIL: APP_IN_RDY stuck\n"); g_fail++; }

    /* Server pushes a response, steps, pump back to client. */
    const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    size_t resp_len = strlen(resp);
    {
        pw_iov_t iov[2] = {
            { .base = (const uint8_t*)resp,           .len = 17 },
            { .base = (const uint8_t*)resp + 17,      .len = resp_len - 17 },
        };
        if (pw_tls_app_out_push(svr, iov, 2) == 0)
             { printf("  PASS: server app_out_push 2-iov response\n"); g_pass++; }
        else { printf("  FAIL: server push\n"); g_fail++; goto out; }
    }
    pw_tls_step(svr);

    /* Pump server TX -> client RX. */
    {
        size_t svr_tx_len;
        const uint8_t* svr_tx = pw_tls_tx_buf(svr, &svr_tx_len);
        size_t cap;
        uint8_t* dst = pw_tls_rx_buf(cli, &cap);
        memcpy(dst, svr_tx, svr_tx_len);
        pw_tls_rx_ack(cli, svr_tx_len);
        pw_tls_tx_ack(svr, svr_tx_len);
    }
    pw_tls_step(cli);
    {
        size_t pt_len;
        const uint8_t* pt = pw_tls_app_in_buf(cli, &pt_len);
        if (pt_len == resp_len && memcmp(pt, resp, resp_len) == 0)
             { printf("  PASS: client APP_IN matches server response\n"); g_pass++; }
        else { printf("  FAIL: client got %zu B\n", pt_len); g_fail++; }
        pw_tls_app_in_ack(cli, pt_len);
    }

    /* ---------- Round-trip 2: prove seq numbers advance ---------- */
    {
        const char* req2 = "PING";
        pw_iov_t iov = { .base = (const uint8_t*)req2, .len = 4 };
        pw_tls_app_out_push(cli, &iov, 1);
        pw_tls_step(cli);
        size_t tx_len;
        const uint8_t* tx = pw_tls_tx_buf(cli, &tx_len);
        size_t cap;
        uint8_t* dst = pw_tls_rx_buf(svr, &cap);
        memcpy(dst, tx, tx_len);
        pw_tls_rx_ack(svr, tx_len);
        pw_tls_tx_ack(cli, tx_len);
        pw_tls_step(svr);
        size_t pt_len;
        const uint8_t* pt = pw_tls_app_in_buf(svr, &pt_len);
        if (pt_len == 4 && memcmp(pt, "PING", 4) == 0)
             { printf("  PASS: 2nd record decrypts (seq advanced)\n"); g_pass++; }
        else { printf("  FAIL: 2nd record pt_len=%zu\n", pt_len); g_fail++; }
        pw_tls_app_in_ack(svr, pt_len);

        /* RFC 8446 §5.3: per-direction record sequence MUST be the
         * count of records in that direction (0, 1, 2, ...). After
         * sending 2 records cli->svr the sender's write seq must be
         * exactly 2 (next nonce will use seq=2 for the 3rd record).
         * Catches the double-bump regression where seq would jump
         * 0 -> 2 -> 4. */
        if (cli->write.seq == 2 && svr->read.seq == 2)
             { printf("  PASS: seq counters canonical (cli.write=svr.read=2)\n"); g_pass++; }
        else { printf("  FAIL: seq cli.w=%llu svr.r=%llu (want 2/2)\n",
                      (unsigned long long)cli->write.seq,
                      (unsigned long long)svr->read.seq); g_fail++; }
    }

    /* ---------- Tampered tag is detected, state -> FAILED ---------- */
    {
        pw_tls_engine_t* a = malloc(sizeof(*a));
        pw_tls_engine_t* b = malloc(sizeof(*b));
        pw_tls_engine_init(a); pw_tls_engine_init(b);
        test_install_symmetric_keys(a, b);

        const uint8_t junk[] = "ZZZZ";
        pw_iov_t iov = { .base = junk, .len = 4 };
        pw_tls_app_out_push(b, &iov, 1);
        pw_tls_step(b);
        size_t tx_len;
        const uint8_t* tx = pw_tls_tx_buf(b, &tx_len);

        /* Pump to a, but flip a tag byte first. */
        size_t cap;
        uint8_t* dst = pw_tls_rx_buf(a, &cap);
        memcpy(dst, tx, tx_len);
        dst[tx_len - 1] ^= 0x42;     /* corrupt last byte (in tag) */
        pw_tls_rx_ack(a, tx_len);

        int rc = pw_tls_step(a);
        if (rc == -1 && pw_tls_state(a) == PW_TLS_ST_FAILED)
             { printf("  PASS: tampered tag -> step returns -1, state FAILED\n"); g_pass++; }
        else { printf("  FAIL: rc=%d state=%d\n", rc, pw_tls_state(a)); g_fail++; }

        free(a); free(b);
    }

    /* ---------- close transitions to CLOSED ---------- */
    pw_tls_close(svr);
    if (pw_tls_state(svr) == PW_TLS_ST_CLOSED)
         { printf("  PASS: pw_tls_close -> CLOSED\n"); g_pass++; }
    else { printf("  FAIL: state=%d\n", pw_tls_state(svr)); g_fail++; }

out:
    free(svr);
    free(cli);
}

/* ====================================================================
 * Engine plugged behind dispatch: TLS service on a port
 * ==================================================================== */

/* A tiny TLS-echo service: decrypts, copies plaintext back as the
 * response. Demonstrates engine + dispatch composition. */

typedef struct {
    pw_tls_engine_t* eng;
    /* Long-lived response buffer the iov_out points at. */
    uint8_t  reply_cipher[PW_TLS_BUF_CAP];
    size_t   reply_cipher_len;
} tls_echo_conn_t;

typedef struct {
    /* Pool of two so we can verify the reuse path. */
    tls_echo_conn_t  pool[2];
    pw_tls_engine_t  engs[2];
    int              opened, closed;
    /* Symmetric keys to install on each new conn. */
    uint8_t  ck[32], civ[12], sk[32], siv[12];
} tls_echo_svc_t;

static void* tls_echo_open(void* svc_state, const pw_conn_info_t* info) {
    (void)info;
    tls_echo_svc_t* s = svc_state;
    for (int i = 0; i < 2; i++) {
        if (s->pool[i].eng == NULL) {
            s->pool[i].eng = &s->engs[i];
            s->pool[i].reply_cipher_len = 0;
            pw_tls_engine_init(s->pool[i].eng);
            pw_tls_engine_install_app_keys(s->pool[i].eng,
                                           s->ck, s->civ, s->sk, s->siv, 1);
            s->opened++;
            return &s->pool[i];
        }
    }
    return NULL;
}

static pw_disp_status_t tls_echo_data(void* per_conn_state,
                                      const uint8_t* data, size_t len,
                                      pw_iov_t* iov_out, unsigned iov_max,
                                      unsigned* iov_n) {
    (void)iov_max;
    tls_echo_conn_t* c = per_conn_state;
    *iov_n = 0;

    /* Inject ciphertext, step. */
    size_t cap;
    uint8_t* dst = pw_tls_rx_buf(c->eng, &cap);
    if (len > cap) return PW_DISP_ERROR;
    memcpy(dst, data, len);
    pw_tls_rx_ack(c->eng, len);
    if (pw_tls_step(c->eng) < 0) return PW_DISP_RESET;

    /* Drain plaintext, push back through the engine as response. */
    size_t pt_len;
    const uint8_t* pt = pw_tls_app_in_buf(c->eng, &pt_len);
    if (pt_len) {
        pw_iov_t iov = { .base = pt, .len = pt_len };
        if (pw_tls_app_out_push(c->eng, &iov, 1) != 0) return PW_DISP_ERROR;
        pw_tls_app_in_ack(c->eng, pt_len);
        pw_tls_step(c->eng);
    }

    /* Pull sealed bytes out of TX into the long-lived reply_cipher
     * buffer (which iov_out points at). */
    size_t tx_len;
    const uint8_t* tx = pw_tls_tx_buf(c->eng, &tx_len);
    if (tx_len) {
        if (tx_len > sizeof(c->reply_cipher)) return PW_DISP_ERROR;
        memcpy(c->reply_cipher, tx, tx_len);
        c->reply_cipher_len = tx_len;
        pw_tls_tx_ack(c->eng, tx_len);
        iov_out[0].base = c->reply_cipher;
        iov_out[0].len  = c->reply_cipher_len;
        *iov_n = 1;
        return PW_DISP_OUTPUT;
    }
    return PW_DISP_NO_OUTPUT;
}

static void tls_echo_close(void* per_conn_state) {
    tls_echo_conn_t* c = per_conn_state;
    if (c->eng) { pw_tls_close(c->eng); c->eng = NULL; }
    extern tls_echo_svc_t* g_active_tls_echo;
    if (g_active_tls_echo) g_active_tls_echo->closed++;
}

tls_echo_svc_t* g_active_tls_echo = NULL;

static void test_engine_via_dispatch(void) {
    printf("== TLS engine plugged behind dispatch (port 443 = TLS-echo) ==\n");

    /* Build the echo service with symmetric keys. */
    tls_echo_svc_t* svc = calloc(1, sizeof(*svc));
    if (!svc) { printf("  FAIL: alloc\n"); g_fail++; return; }
    for (int i = 0; i < 32; i++) svc->ck[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 12; i++) svc->civ[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 32; i++) svc->sk[i] = (uint8_t)(0x80 + i);
    for (int i = 0; i < 12; i++) svc->siv[i] = (uint8_t)(0xa0 + i);
    g_active_tls_echo = svc;

    /* A peer engine for the "client" side. */
    pw_tls_engine_t* peer = malloc(sizeof(*peer));
    pw_tls_engine_init(peer);
    pw_tls_engine_install_app_keys(peer, svc->ck, svc->civ, svc->sk, svc->siv, 0);

    /* Build the dispatch + TCP stack and register the TLS-echo service. */
    pw_service_t s = {
        .proto = PW_PROTO_TCP, .port = 443,
        .svc_state = svc,
        .on_open  = tls_echo_open,
        .on_data  = tls_echo_data,
        .on_close = tls_echo_close,
    };
    pw_dispatch_t disp; pw_dispatch_init(&disp);
    pw_dispatch_register(&disp, &s);
    tcp_stack_t stack;
    tcp_attach_dispatch(&stack, 0x0a000002u, &disp);

    /* Drive one TCP handshake on port 443. */
    emit_log_t log = {0};
    tcp_seg_t syn = {0};
    syn.src_ip=0x0a000001u; syn.dst_ip=0x0a000002u;
    syn.src_port=4242;     syn.dst_port=443;
    syn.seq=1000; syn.flags=TCPF_SYN; syn.window=65535;
    tcp_input(&stack, &syn, NULL, NULL, log_emit, &log);
    uint32_t srv_iss = log.segs[0].seq;

    log.n = 0;
    tcp_seg_t ack = {0};
    ack.src_ip=0x0a000001u; ack.dst_ip=0x0a000002u;
    ack.src_port=4242;     ack.dst_port=443;
    ack.seq=1001; ack.ack=srv_iss+1; ack.flags=TCPF_ACK; ack.window=65535;
    tcp_input(&stack, &ack, NULL, NULL, log_emit, &log);

    if (svc->opened == 1)
         { printf("  PASS: TLS service on_open fired at ESTABLISHED\n"); g_pass++; }
    else { printf("  FAIL: opened=%d\n", svc->opened); g_fail++; }

    /* Client engine seals "echo me!" into a TLS record. */
    const char* msg = "echo me!";
    pw_iov_t iov = { .base = (const uint8_t*)msg, .len = strlen(msg) };
    pw_tls_app_out_push(peer, &iov, 1);
    pw_tls_step(peer);
    size_t cipher_len;
    const uint8_t* cipher = pw_tls_tx_buf(peer, &cipher_len);

    /* Send that ciphertext over TCP to the dispatched TLS service. */
    log.n = 0;
    tcp_seg_t pkt = {0};
    pkt.src_ip=0x0a000001u; pkt.dst_ip=0x0a000002u;
    pkt.src_port=4242;     pkt.dst_port=443;
    pkt.seq=1001; pkt.ack=srv_iss+1;
    pkt.flags=TCPF_ACK|TCPF_PSH; pkt.window=65535;
    pkt.payload=cipher; pkt.payload_len=cipher_len;
    tcp_input(&stack, &pkt, NULL, NULL, log_emit, &log);

    /* Find the data-bearing reply segment, feed it into the peer's
     * RX, decrypt, and check we got "echo me!" back. */
    int saw_data = 0;
    for (int i = 0; i < log.n; i++) {
        if (log.segs[i].payload_len > 0) {
            size_t cap;
            uint8_t* dst = pw_tls_rx_buf(peer, &cap);
            memcpy(dst, log.segs[i].payload, log.segs[i].payload_len);
            pw_tls_rx_ack(peer, log.segs[i].payload_len);
            pw_tls_step(peer);
            size_t pt_len;
            const uint8_t* pt = pw_tls_app_in_buf(peer, &pt_len);
            if (pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0)
                saw_data = 1;
            pw_tls_app_in_ack(peer, pt_len);
        }
    }
    if (saw_data)
         { printf("  PASS: round-trip 'echo me!' through dispatch->engine->dispatch\n"); g_pass++; }
    else { printf("  FAIL: no echo back\n"); g_fail++; }

    /* Tear down. Send FIN and check close fires. */
    log.n = 0;
    tcp_seg_t fin = {0};
    fin.src_ip=0x0a000001u; fin.dst_ip=0x0a000002u;
    fin.src_port=4242;     fin.dst_port=443;
    fin.seq=1001+cipher_len; fin.ack=srv_iss+1;
    fin.flags=TCPF_FIN|TCPF_ACK; fin.window=65535;
    tcp_input(&stack, &fin, NULL, NULL, log_emit, &log);
    if (svc->closed == 1)
         { printf("  PASS: on_close fired exactly once on FIN\n"); g_pass++; }
    else { printf("  FAIL: closed=%d\n", svc->closed); g_fail++; }

    free(peer);
    free(svc);
    g_active_tls_echo = NULL;
}

/* ============================================================ *
 * Engine handshake driver tests (server-side)
 *
 * These exercise pw_tls_engine_configure_server + the new CH -> SH
 * + install-handshake-traffic-keys path inside pw_tls_step.
 * ============================================================ */

/* Deterministic counter-based RNG so traffic keys are reproducible
 * (lets us derive expected values independently and compare). */
typedef struct {
    uint8_t next;
} test_rng_state_t;

static int test_rng(void* user, uint8_t* dst, size_t n) {
    test_rng_state_t* s = (test_rng_state_t*)user;
    for (size_t i = 0; i < n; i++) dst[i] = s->next++;
    return 0;
}

/* Build a synthetic ClientHello as a TLSPlaintext record into out[..].
 * Returns total record length. The body is a single ClientHello msg.
 *
 *   sni      — pointer to ASCII hostname (NULL or empty -> no SNI ext)
 *   client_pub[32] — X25519 pubkey to put in the key_share
 *   session_id, sid_len — what to put in legacy_session_id
 *   include_ed25519 — if 0, signature_algorithms lists 0x0403
 *                     (ecdsa_secp256r1_sha256) only, simulating a
 *                     client that does not advertise ed25519.
 *   include_chacha — if 0, cipher_suites lists 0x1301 only
 *                    (TLS_AES_128_GCM_SHA256), no chacha. */
static size_t build_test_ch_record(uint8_t* out, size_t out_cap,
                                   const uint8_t client_pub[32],
                                   const uint8_t* session_id,
                                   uint8_t sid_len,
                                   const char* sni,
                                   int include_ed25519,
                                   int include_chacha) {
    if (out_cap < 256) return 0;
    /* Reserve 5 bytes for the record header at the start. */
    uint8_t* rec_hdr = out;
    uint8_t* p = out + TLS13_RECORD_HEADER_LEN;
    /* Handshake header */
    w8(&p, 0x01);
    uint8_t* hs_len_at = p; w24(&p, 0);
    uint8_t* hs_body = p;

    w16(&p, 0x0303);                              /* legacy_version */
    for (int i = 0; i < 32; i++) w8(&p, (uint8_t)i);
    /* legacy_session_id */
    w8(&p, sid_len);
    if (sid_len) wb(&p, session_id, sid_len);
    /* cipher_suites */
    if (include_chacha) {
        w16(&p, 2);
        w16(&p, TLS13_CHACHA20_POLY1305_SHA256);
    } else {
        w16(&p, 2);
        w16(&p, 0x1301);                          /* TLS_AES_128_GCM_SHA256 */
    }
    /* compression_methods */
    w8(&p, 1); w8(&p, 0);
    /* extensions */
    uint8_t* ext_len_at = p; w16(&p, 0);
    uint8_t* ext_start = p;
    /* SNI */
    if (sni && *sni) {
        uint16_t host_len = (uint16_t)strlen(sni);
        w16(&p, 0x0000);
        w16(&p, 2 + 1 + 2 + host_len);
        w16(&p, 1 + 2 + host_len);
        w8 (&p, 0);
        w16(&p, host_len);
        wb (&p, sni, host_len);
    }
    /* supported_groups: x25519 */
    w16(&p, 0x000a); w16(&p, 4);
    w16(&p, 2); w16(&p, TLS13_NAMED_GROUP_X25519);
    /* key_share: x25519 + client_pub */
    w16(&p, 0x0033); w16(&p, 2 + 4 + 32);
    w16(&p, 4 + 32);
    w16(&p, TLS13_NAMED_GROUP_X25519);
    w16(&p, 32); wb(&p, client_pub, 32);
    /* supported_versions: TLS 1.3 */
    w16(&p, 0x002b); w16(&p, 1 + 2);
    w8(&p, 2); w16(&p, TLS13_SUPPORTED_VERSION);
    /* signature_algorithms */
    w16(&p, 0x000d);
    w16(&p, 2 + 2);
    w16(&p, 2);
    w16(&p, include_ed25519 ? TLS13_SIG_SCHEME_ED25519 : 0x0403);

    uint16_t ext_len = (uint16_t)(p - ext_start);
    ext_len_at[0] = ext_len >> 8; ext_len_at[1] = (uint8_t)ext_len;
    uint32_t hs_len = (uint32_t)(p - hs_body);
    hs_len_at[0] = (uint8_t)(hs_len >> 16);
    hs_len_at[1] = (uint8_t)(hs_len >> 8);
    hs_len_at[2] = (uint8_t)hs_len;

    /* Backfill TLSPlaintext record header. Body length = bytes
     * from end-of-record-header to p. */
    size_t body_len = (size_t)(p - (out + TLS13_RECORD_HEADER_LEN));
    rec_hdr[0] = TLS_CT_HANDSHAKE;
    rec_hdr[1] = 0x03; rec_hdr[2] = 0x03;
    rec_hdr[3] = (uint8_t)(body_len >> 8);
    rec_hdr[4] = (uint8_t)body_len;

    return TLS13_RECORD_HEADER_LEN + body_len;
}

static void test_engine_handshake_server(void) {
    printf("== TLS engine: server-side CH -> SH + install handshake keys ==\n");

    /* Synthetic config: zero seed (we don't verify a sig in commit A),
     * a single 4-byte fake DER cert. The handshake driver doesn't
     * touch these in commit A — they're stashed for commit B. */
    uint8_t seed[32] = {0};
    const uint8_t fake_cert[4] = { 0x30, 0x02, 0x05, 0x00 };
    const size_t  fake_lens[1] = { 4 };

    /* Deterministic RNG: 0,1,2,3,... */
    test_rng_state_t rng_st = { .next = 0 };

    /* Generate a realistic-looking client X25519 pubkey. */
    uint8_t client_priv[32];
    for (int i = 0; i < 32; i++) client_priv[i] = (uint8_t)(0x80 + i);
    uint8_t client_pub[32];
    x25519(client_pub, client_priv, X25519_BASE_POINT);

    /* ---------- happy path ---------- */
    {
        pw_tls_engine_t* eng = malloc(sizeof(*eng));
        if (!eng) { printf("  FAIL: alloc\n"); g_fail++; return; }
        pw_tls_engine_init(eng);
        if (pw_tls_engine_configure_server(eng, test_rng, &rng_st, seed,
                                           fake_cert, fake_lens, 1) == 0)
             { printf("  PASS: configure_server accepted\n"); g_pass++; }
        else { printf("  FAIL: configure_server\n"); g_fail++; free(eng); return; }

        /* Build a CH with a non-empty session_id (compat-mode browsers
         * send 32 random bytes here; the server MUST echo). */
        uint8_t sid[32];
        for (int i = 0; i < 32; i++) sid[i] = (uint8_t)(0xC0 + i);

        uint8_t ch_rec[2048];
        size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec),
                                              client_pub, sid, 32,
                                              "example.com", 1, 1);
        if (ch_len == 0) { printf("  FAIL: build CH\n"); g_fail++; free(eng); return; }

        /* Push CH into engine RX. */
        size_t cap;
        uint8_t* rx = pw_tls_rx_buf(eng, &cap);
        if (cap < ch_len) { printf("  FAIL: rx cap\n"); g_fail++; free(eng); return; }
        memcpy(rx, ch_rec, ch_len);
        pw_tls_rx_ack(eng, ch_len);

        int want = pw_tls_step(eng);
        if (want >= 0) { printf("  PASS: step accepted CH (want=0x%x)\n", want); g_pass++; }
        else           { printf("  FAIL: step rc=%d\n", want); g_fail++; free(eng); return; }

        if (pw_tls_state(eng) == PW_TLS_ST_HANDSHAKE)
             { printf("  PASS: state still HANDSHAKE\n"); g_pass++; }
        else { printf("  FAIL: state=%d\n", pw_tls_state(eng)); g_fail++; }

        /* The engine drives forward in a single step: CH -> SH ->
         * install hs keys -> emit encrypted EE/Cert/CV/sFin. After
         * that it sits in AFTER_SF_AWAIT_CF waiting for client Fin. */
        if (pw_tls_hs_phase(eng) == PW_TLS_HS_AFTER_SF_AWAIT_CF)
             { printf("  PASS: hs_phase advanced to AFTER_SF_AWAIT_CF\n"); g_pass++; }
        else { printf("  FAIL: hs_phase=%d\n", pw_tls_hs_phase(eng)); g_fail++; }

        if (eng->keys_installed)
             { printf("  PASS: handshake-traffic keys installed\n"); g_pass++; }
        else { printf("  FAIL: keys_installed=0\n"); g_fail++; }

        /* TX: first record is the plaintext SH; then 4 encrypted
         * application_data records (EE, Cert, CV, sFin). */
        size_t tx_len;
        const uint8_t* tx = pw_tls_tx_buf(eng, &tx_len);
        int sh_ok = (tx_len >= TLS13_RECORD_HEADER_LEN + 4)
                 && tx[0] == TLS_CT_HANDSHAKE
                 && tx[1] == 0x03 && tx[2] == 0x03
                 && tx[TLS13_RECORD_HEADER_LEN] == 0x02; /* server_hello */
        if (sh_ok) { printf("  PASS: TX[0] is plaintext SH record\n"); g_pass++; }
        else       { printf("  FAIL: TX[0..]=%02x %02x %02x ... [hdr_msg]=%02x\n",
                            tx[0],tx[1],tx[2],
                            tx_len > TLS13_RECORD_HEADER_LEN ?
                                tx[TLS13_RECORD_HEADER_LEN] : 0); g_fail++; }

        /* SH must echo the CH session_id verbatim. The session_id sits
         * at offset (record_hdr 5) + (hs_hdr 4) + legacy_version 2 +
         * random 32 = 43; one byte len then the bytes. */
        if (tx_len >= 43 + 1 + 32) {
            int echo_ok = (tx[43] == 32) && memcmp(tx + 44, sid, 32) == 0;
            if (echo_ok) { printf("  PASS: SH echoes legacy_session_id\n"); g_pass++; }
            else         { printf("  FAIL: SH session_id len=%u\n", tx[43]); g_fail++; }
        } else {
            printf("  FAIL: SH too short for session_id check\n"); g_fail++;
        }

        /* After SH there must be 4 encrypted application_data records
         * (EE, Cert, CV, sFin). Don't decrypt — that's the integration
         * test's job. Just count them. */
        {
            uint16_t sh_body = ((uint16_t)tx[3] << 8) | tx[4];
            size_t off = TLS13_RECORD_HEADER_LEN + sh_body;
            int n_enc = 0;
            while (off + TLS13_RECORD_HEADER_LEN <= tx_len) {
                if (tx[off] != TLS_CT_APPLICATION_DATA) break;
                uint16_t rl = ((uint16_t)tx[off+3] << 8) | tx[off+4];
                if (off + TLS13_RECORD_HEADER_LEN + rl > tx_len) break;
                off += TLS13_RECORD_HEADER_LEN + rl;
                n_enc++;
            }
            if (n_enc == 4) { printf("  PASS: 4 encrypted records follow SH (EE/Cert/CV/sFin)\n"); g_pass++; }
            else            { printf("  FAIL: %d encrypted records after SH\n", n_enc); g_fail++; }
        }

        /* Independently re-derive the read+write keys and verify they
         * match what the engine installed. Re-run the same RNG sequence
         * against a parallel computation. */
        {
            test_rng_state_t rng2 = { .next = 0 };
            uint8_t srv_random[32], srv_priv[32];
            test_rng(&rng2, srv_random, 32);
            test_rng(&rng2, srv_priv,   32);
            srv_priv[0]  &= 248;
            srv_priv[31] &= 127;
            srv_priv[31] |= 64;
            uint8_t srv_pub[32];
            x25519(srv_pub, srv_priv, X25519_BASE_POINT);

            uint8_t ref_sh[256];
            int ref_sh_len = tls13_build_server_hello(ref_sh, sizeof(ref_sh),
                                                     srv_random, srv_pub,
                                                     sid, 32);
            uint8_t shared_ref[32];
            x25519(shared_ref, srv_priv, client_pub);

            tls13_transcript_t t;
            tls13_transcript_init(&t);
            /* CH msg portion is the inner handshake msg, which is the
             * record body without the 5-byte record header. */
            tls13_transcript_update(&t,
                                    ch_rec + TLS13_RECORD_HEADER_LEN,
                                    ch_len - TLS13_RECORD_HEADER_LEN);
            tls13_transcript_update(&t, ref_sh, (size_t)ref_sh_len);
            uint8_t th[32];
            tls13_transcript_snapshot(&t, th);

            uint8_t hs_secret[32], cs_hs[32], ss_hs[32];
            tls13_compute_handshake_secrets(shared_ref, th,
                                            hs_secret, cs_hs, ss_hs);
            uint8_t kref[32], ivref[12];
            tls13_derive_traffic_keys(cs_hs, kref, ivref);
            int read_ok  = memcmp(eng->read.key, kref, 32) == 0
                        && memcmp(eng->read.static_iv, ivref, 12) == 0
                        && eng->read.seq == 0;
            tls13_derive_traffic_keys(ss_hs, kref, ivref);
            /* eng->write has sealed 4 encrypted handshake records by
             * now (EE/Cert/CV/sFin) so seq has advanced to 4; the key
             * and iv are still the server-handshake-traffic ones. */
            int write_ok = memcmp(eng->write.key, kref, 32) == 0
                        && memcmp(eng->write.static_iv, ivref, 12) == 0
                        && eng->write.seq == 4;
            if (read_ok)  { printf("  PASS: engine.read keys match independent derive\n"); g_pass++; }
            else          { printf("  FAIL: engine.read keys mismatch\n"); g_fail++; }
            if (write_ok) { printf("  PASS: engine.write keys match independent derive\n"); g_pass++; }
            else          { printf("  FAIL: engine.write keys mismatch (seq=%llu)\n",
                                  (unsigned long long)eng->write.seq); g_fail++; }

            /* The first record's SH bytes the engine emitted should
             * match our reference SH byte-for-byte (deterministic RNG
             * -> same server_random and same server_pub). */
            if (tx_len >= TLS13_RECORD_HEADER_LEN + (size_t)ref_sh_len
                && memcmp(tx + TLS13_RECORD_HEADER_LEN, ref_sh, (size_t)ref_sh_len) == 0)
                 { printf("  PASS: emitted SH matches reference byte-for-byte\n"); g_pass++; }
            else { printf("  FAIL: SH bytes differ from reference\n"); g_fail++; }
        }

        /* eph_priv must have been wiped after key install. */
        {
            uint8_t acc = 0;
            for (size_t i = 0; i < 32; i++) acc |= eng->eph_priv[i];
            if (acc == 0) { printf("  PASS: eph_priv wiped after install\n"); g_pass++; }
            else          { printf("  FAIL: eph_priv not wiped\n"); g_fail++; }
        }

        free(eng);
    }

    /* ---------- negative: no ed25519 in sig_algs ---------- */
    {
        pw_tls_engine_t* eng = malloc(sizeof(*eng));
        pw_tls_engine_init(eng);
        rng_st.next = 0;
        pw_tls_engine_configure_server(eng, test_rng, &rng_st, seed,
                                       fake_cert, fake_lens, 1);

        uint8_t ch_rec[2048];
        size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec),
                                              client_pub, NULL, 0,
                                              "example.com", 0, 1);
        size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
        memcpy(rx, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);

        int rc = pw_tls_step(eng);
        if (rc < 0 && pw_tls_state(eng) == PW_TLS_ST_FAILED)
             { printf("  PASS: CH without ed25519 -> FAILED\n"); g_pass++; }
        else { printf("  FAIL: rc=%d state=%d\n", rc, pw_tls_state(eng)); g_fail++; }

        /* TX MUST be empty — nothing should leak before the rejection. */
        size_t tx_len; (void)pw_tls_tx_buf(eng, &tx_len);
        if (tx_len == 0) { printf("  PASS: no SH leaked on rejection\n"); g_pass++; }
        else             { printf("  FAIL: tx_len=%zu after reject\n", tx_len); g_fail++; }

        free(eng);
    }

    /* ---------- negative: no chacha in cipher_suites ---------- */
    {
        pw_tls_engine_t* eng = malloc(sizeof(*eng));
        pw_tls_engine_init(eng);
        rng_st.next = 0;
        pw_tls_engine_configure_server(eng, test_rng, &rng_st, seed,
                                       fake_cert, fake_lens, 1);

        uint8_t ch_rec[2048];
        size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec),
                                              client_pub, NULL, 0,
                                              "example.com", 1, 0);
        size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
        memcpy(rx, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);

        int rc = pw_tls_step(eng);
        if (rc < 0 && pw_tls_state(eng) == PW_TLS_ST_FAILED)
             { printf("  PASS: CH without chacha -> FAILED\n"); g_pass++; }
        else { printf("  FAIL: rc=%d state=%d\n", rc, pw_tls_state(eng)); g_fail++; }
        free(eng);
    }

    /* ---------- negative: low-order share -> all-zero shared ---------- */
    {
        pw_tls_engine_t* eng = malloc(sizeof(*eng));
        pw_tls_engine_init(eng);
        rng_st.next = 0;
        pw_tls_engine_configure_server(eng, test_rng, &rng_st, seed,
                                       fake_cert, fake_lens, 1);

        uint8_t low_order[32] = {0}; /* point at infinity, X25519 -> 0 */
        uint8_t ch_rec[2048];
        size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec),
                                              low_order, NULL, 0,
                                              "example.com", 1, 1);
        size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
        memcpy(rx, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);

        int rc = pw_tls_step(eng);
        if (rc < 0 && pw_tls_state(eng) == PW_TLS_ST_FAILED)
             { printf("  PASS: low-order share -> FAILED\n"); g_pass++; }
        else { printf("  FAIL: rc=%d state=%d\n", rc, pw_tls_state(eng)); g_fail++; }

        /* CRITICAL: TX MUST be empty. The whole point of the SH-after-
         * shared-check ordering is to avoid leaking ServerHello bytes
         * on a hostile low-order pubkey. */
        size_t tx_len; (void)pw_tls_tx_buf(eng, &tx_len);
        if (tx_len == 0) { printf("  PASS: no SH leaked on low-order share\n"); g_pass++; }
        else             { printf("  FAIL: tx_len=%zu after low-order reject\n", tx_len); g_fail++; }

        free(eng);
    }

    /* ---------- partial: truncated CH -> step returns 0, no transition --- */
    {
        pw_tls_engine_t* eng = malloc(sizeof(*eng));
        pw_tls_engine_init(eng);
        rng_st.next = 0;
        pw_tls_engine_configure_server(eng, test_rng, &rng_st, seed,
                                       fake_cert, fake_lens, 1);

        uint8_t ch_rec[2048];
        size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec),
                                              client_pub, NULL, 0,
                                              "example.com", 1, 1);
        /* Drop the last byte. */
        size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
        memcpy(rx, ch_rec, ch_len - 1); pw_tls_rx_ack(eng, ch_len - 1);

        int want = pw_tls_step(eng);
        int ok = (want >= 0)
              && pw_tls_state(eng) == PW_TLS_ST_HANDSHAKE
              && pw_tls_hs_phase(eng) == PW_TLS_HS_WAIT_CH;
        if (ok) { printf("  PASS: truncated CH waits for more bytes\n"); g_pass++; }
        else    { printf("  FAIL: want=%d state=%d phase=%d\n",
                         want, pw_tls_state(eng), pw_tls_hs_phase(eng)); g_fail++; }
        free(eng);
    }

    /* ---------- not configured: step is a no-op in HANDSHAKE ----------- */
    {
        pw_tls_engine_t* eng = malloc(sizeof(*eng));
        pw_tls_engine_init(eng);
        /* Do NOT call configure_server. */
        uint8_t ch_rec[2048];
        size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec),
                                              client_pub, NULL, 0,
                                              "example.com", 1, 1);
        size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
        memcpy(rx, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);

        int want = pw_tls_step(eng);
        if (want >= 0 && pw_tls_state(eng) == PW_TLS_ST_HANDSHAKE
                      && pw_tls_hs_phase(eng) == PW_TLS_HS_WAIT_CH)
             { printf("  PASS: unconfigured engine no-ops in HANDSHAKE\n"); g_pass++; }
        else { printf("  FAIL: want=%d state=%d\n", want, pw_tls_state(eng)); g_fail++; }
        free(eng);
    }
}

/* ============================================================
 *  Full TLS 1.3 server-side handshake roundtrip through the engine.
 *  The test mirrors a real client by:
 *   - generating an X25519 keypair
 *   - building a CH and pushing to the engine
 *   - parsing the SH the engine emits, deriving handshake secrets
 *   - decrypting EE/Cert/CV/sFin, verifying CV signature + sFin
 *   - deriving app secrets independently
 *   - building + encrypting client Finished, pushing to engine RX
 *   - asserting state transitions to APP and engine app-keys match
 *   - sending one app-data record from "client" to "server", asserting
 *     the engine surfaces the plaintext via APP_IN
 * ============================================================ */
static void test_engine_handshake_roundtrip(void) {
    printf("== TLS engine: full server handshake roundtrip ==\n");

    /* ---- Server identity: deterministic ed25519 seed (not secret in
     * this test). The engine uses this to sign CV. ---- */
    uint8_t srv_seed[32];
    for (int i = 0; i < 32; i++) srv_seed[i] = 0x40 + (uint8_t)i;
    uint8_t srv_pub[32];
    ed25519_pubkey_from_seed(srv_pub, srv_seed);

    /* Build a fake DER cert chain. The engine just shovels these
     * bytes into the Certificate handshake message; we check the
     * length round-trip but never parse them as real ASN.1. */
    const uint8_t fake_cert[64] = {
        0x30, 0x3e, 0x05, 0x00, /* trivial-looking SEQUENCE+NULL */
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };
    const uint8_t* cert_chain = fake_cert;
    size_t         cert_lens[1]  = { sizeof(fake_cert) };

    /* ---- Client identity: hard-wired X25519 priv (RFC 7748 §6.1
     * Alice's private key would do, but any 32 bytes are fine).
     * Compute pub via x25519(priv, base). ---- */
    uint8_t cli_priv[32];
    for (int i = 0; i < 32; i++) cli_priv[i] = 0x77 ^ (uint8_t)i;
    cli_priv[0]  &= 248;
    cli_priv[31] &= 127;
    cli_priv[31] |= 64;
    uint8_t cli_pub[32];
    x25519(cli_pub, cli_priv, X25519_BASE_POINT);

    /* ---- Configure the engine. Deterministic test_rng so both
     * server_random and the server's eph priv are reproducible. ---- */
    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    test_rng_state_t rng_st = { .next = 0 };
    if (pw_tls_engine_configure_server(eng, test_rng, &rng_st, srv_seed,
                                       cert_chain, cert_lens, 1) == 0)
         { printf("  PASS: configure_server\n"); g_pass++; }
    else { printf("  FAIL: configure_server\n"); g_fail++; free(eng); return; }

    /* The two random reads test_rng will satisfy from server side
     * (server_random[32], then server_eph_priv[32]) come out as
     * 0..31 and 32..63 thanks to the counter RNG. */
    uint8_t srv_random_expected[32];
    uint8_t srv_eph_priv_clamped[32];
    {
        test_rng_state_t r = { .next = 0 };
        test_rng(&r, srv_random_expected, 32);
        test_rng(&r, srv_eph_priv_clamped, 32);
        srv_eph_priv_clamped[0]  &= 248;
        srv_eph_priv_clamped[31] &= 127;
        srv_eph_priv_clamped[31] |= 64;
    }
    uint8_t srv_pub_eph[32];
    x25519(srv_pub_eph, srv_eph_priv_clamped, X25519_BASE_POINT);
    uint8_t shared[32];
    x25519(shared, cli_priv, srv_pub_eph);

    /* ---- Build CH and feed it to the engine. ---- */
    uint8_t  ch_rec[2048];
    uint8_t  sid[32]; for (int i = 0; i < 32; i++) sid[i] = 0xa0 + (uint8_t)i;
    size_t   ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec),
                                           cli_pub, sid, 32,
                                           "example.com", 1, 1);
    if (ch_len == 0) { printf("  FAIL: build CH\n"); g_fail++; free(eng); return; }

    size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
    memcpy(rx, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);

    int want = pw_tls_step(eng);
    if (want >= 0 && pw_tls_state(eng) == PW_TLS_ST_HANDSHAKE
                  && pw_tls_hs_phase(eng) == PW_TLS_HS_AFTER_SF_AWAIT_CF)
         { printf("  PASS: engine drove CH -> AFTER_SF_AWAIT_CF\n"); g_pass++; }
    else { printf("  FAIL: want=%d state=%d phase=%d\n",
                  want, pw_tls_state(eng), pw_tls_hs_phase(eng));
           g_fail++; free(eng); return; }

    /* ---- Parse the SH: skip past record header, then walk the
     * server_hello extensions to find key_share -> server pub. We
     * already know what server_pub_eph is (computed independently)
     * but we still want to assert it matches what the engine put on
     * the wire. ---- */
    size_t tx_len; const uint8_t* tx = pw_tls_tx_buf(eng, &tx_len);
    if (tx_len < 5 || tx[0] != TLS_CT_HANDSHAKE)
         { printf("  FAIL: SH header\n"); g_fail++; free(eng); return; }
    uint16_t sh_body = ((uint16_t)tx[3] << 8) | tx[4];
    if ((size_t)sh_body + 5 > tx_len)
         { printf("  FAIL: SH truncated\n"); g_fail++; free(eng); return; }
    const uint8_t* sh_msg = tx + 5;            /* server_hello handshake msg */
    size_t sh_msg_len     = sh_body;

    /* sanity: msg type=0x02 + 24-bit len matches body-4 */
    if (sh_msg[0] != 0x02) { printf("  FAIL: SH msg_type\n"); g_fail++; free(eng); return; }

    /* Handshake transcript: client side, in parallel with the
     * engine's. */
    tls13_transcript_t cli_ts;
    tls13_transcript_init(&cli_ts);

    /* CH body inside the record we built starts at offset 5. */
    tls13_transcript_update(&cli_ts, ch_rec + 5, ch_len - 5);
    /* Then SH msg. */
    tls13_transcript_update(&cli_ts, sh_msg, sh_msg_len);

    /* ---- Derive handshake secrets independently and confirm they
     * match what the engine installed (eng->read uses cs_hs key,
     * eng->write uses ss_hs key). ---- */
    uint8_t T1[32];
    tls13_transcript_snapshot(&cli_ts, T1);
    uint8_t hs_secret[32], cs_hs[32], ss_hs[32];
    if (tls13_compute_handshake_secrets(shared, T1, hs_secret, cs_hs, ss_hs) != 0)
         { printf("  FAIL: derive hs secrets\n"); g_fail++; free(eng); return; }

    /* ---- Decrypt the four encrypted records that follow the SH. ---- */
    tls_record_dir_t cli_read = {0};   /* mirrors the server's WRITE direction */
    tls13_derive_traffic_keys(ss_hs, cli_read.key, cli_read.static_iv);
    cli_read.seq = 0;

    /* Walk records starting at offset 5 + sh_body. Need a scratch
     * copy to decrypt in place. */
    size_t off = 5 + sh_body;
    int got_ee = 0, got_cert = 0, got_cv = 0, got_fin = 0;
    uint8_t srv_cv_sig[64];
    uint8_t srv_fin_vd[32];

    /* T2 transcript snapshot (through Cert) needed to verify CV. */
    uint8_t T2_through_cert[32] = {0};

    while (off + 5 <= tx_len) {
        uint16_t rl = ((uint16_t)tx[off+3] << 8) | tx[off+4];
        if (off + 5 + rl > tx_len) break;
        if (tx[off] != TLS_CT_APPLICATION_DATA) break;

        /* Copy this record into a scratch buffer because tls13_open
         * mutates in place. */
        uint8_t scratch[2048];
        if ((size_t)rl + 5 > sizeof(scratch))
             { printf("  FAIL: encrypted record too big\n"); g_fail++; free(eng); return; }
        memcpy(scratch, tx + off, 5 + rl);

        tls_content_type_t inner = TLS_CT_INVALID;
        uint8_t* pt = NULL; size_t pt_len = 0;
        if (tls13_open_record(&cli_read, scratch, 5 + rl,
                              &inner, &pt, &pt_len) != 0)
             { printf("  FAIL: open record at off=%zu\n", off); g_fail++; free(eng); return; }
        if (inner != TLS_CT_HANDSHAKE)
             { printf("  FAIL: inner type %d\n", (int)inner); g_fail++; free(eng); return; }

        /* Update client-side transcript with the plaintext handshake msg. */
        tls13_transcript_update(&cli_ts, pt, pt_len);

        /* Identify by handshake msg type byte. */
        switch (pt[0]) {
            case 0x08: got_ee = 1; break;
            case 0x0b:
                got_cert = 1;
                /* Snapshot transcript through Cert for CV verify. */
                tls13_transcript_snapshot(&cli_ts, T2_through_cert);
                break;
            case 0x0f:
                got_cv = 1;
                /* CV body: hs hdr 4 + sig_scheme 2 + sig_len 2 + sig 64. */
                if (pt_len < 4 + 2 + 2 + 64)
                     { printf("  FAIL: CV size\n"); g_fail++; free(eng); return; }
                if (pt[4] != 0x08 || pt[5] != 0x07) /* ed25519 */
                     { printf("  FAIL: CV scheme %02x%02x\n", pt[4],pt[5]); g_fail++; free(eng); return; }
                memcpy(srv_cv_sig, pt + 8, 64);
                break;
            case 0x14:
                got_fin = 1;
                if (pt_len != 4 + 32)
                     { printf("  FAIL: sFin size %zu\n", pt_len); g_fail++; free(eng); return; }
                memcpy(srv_fin_vd, pt + 4, 32);
                break;
            default:
                printf("  FAIL: unknown hs msg %02x\n", pt[0]); g_fail++; free(eng); return;
        }

        off += 5 + rl;
    }

    if (got_ee && got_cert && got_cv && got_fin)
         { printf("  PASS: decrypted EE+Cert+CV+sFin from engine\n"); g_pass++; }
    else { printf("  FAIL: missing msgs ee=%d cert=%d cv=%d fin=%d\n",
                  got_ee, got_cert, got_cv, got_fin); g_fail++; free(eng); return; }

    /* ---- Verify CV signature against derived server pubkey + the
     * transcript snapshot through Cert. ---- */
    {
        uint8_t signed_data[TLS13_CV_SIGNED_LEN];
        if (tls13_build_certificate_verify_signed_data(signed_data,
                                                       T2_through_cert,
                                                       1 /*is_server*/) != 0)
             { printf("  FAIL: CV signed data\n"); g_fail++; free(eng); return; }
        if (ed25519_verify(srv_cv_sig, signed_data, sizeof(signed_data), srv_pub) == 1)
             { printf("  PASS: CV signature verifies against server Ed25519 pubkey\n"); g_pass++; }
        else { printf("  FAIL: CV signature\n"); g_fail++; free(eng); return; }
    }

    /* ---- Verify server Finished. T3 = transcript through CV (we
     * already have that captured as T2_through_cert WAS through
     * Certificate; we need a fresh snapshot — but our running
     * transcript has since been updated with CV and sFin too).
     *
     * Workaround: re-derive T3 by feeding only CH..CV into a fresh
     * transcript. Faster trick: tls13_verify_finished + the running
     * transcript snapshot taken *before* sFin was added.  Since we
     * already updated the transcript with sFin, recompute. ---- */
    {
        tls13_transcript_t ts2;
        tls13_transcript_init(&ts2);
        tls13_transcript_update(&ts2, ch_rec + 5, ch_len - 5);
        tls13_transcript_update(&ts2, sh_msg, sh_msg_len);
        /* re-walk decrypted msgs but stop after CV */
        size_t off2 = 5 + sh_body;
        int seen_cv = 0;
        while (off2 + 5 <= tx_len && !seen_cv) {
            uint16_t rl = ((uint16_t)tx[off2+3] << 8) | tx[off2+4];
            uint8_t scratch[2048];
            memcpy(scratch, tx + off2, 5 + rl);
            tls_record_dir_t tmp = {0};
            tls13_derive_traffic_keys(ss_hs, tmp.key, tmp.static_iv);
            /* compute the right seq for this position */
            tmp.seq = 0;
            for (size_t o3 = 5 + sh_body; o3 < off2; ) {
                uint16_t rl3 = ((uint16_t)tx[o3+3] << 8) | tx[o3+4];
                tmp.seq++;
                o3 += 5 + rl3;
            }
            tls_content_type_t inner; uint8_t* pt; size_t pl;
            tls13_open_record(&tmp, scratch, 5 + rl, &inner, &pt, &pl);
            tls13_transcript_update(&ts2, pt, pl);
            if (pt[0] == 0x0f) seen_cv = 1;
            off2 += 5 + rl;
        }
        uint8_t T3[32];
        tls13_transcript_snapshot(&ts2, T3);
        if (tls13_verify_finished(ss_hs, T3, srv_fin_vd) == 0)
             { printf("  PASS: server Finished verifies\n"); g_pass++; }
        else { printf("  FAIL: server Finished\n"); g_fail++; free(eng); return; }
    }

    /* ---- Compute T4 = transcript through sFin (current cli_ts state).
     * Derive app secrets. ---- */
    uint8_t T4[32];
    tls13_transcript_snapshot(&cli_ts, T4);
    uint8_t master[32], cs_app[32], ss_app[32];
    if (tls13_compute_application_secrets(hs_secret, T4, master, cs_app, ss_app) != 0)
         { printf("  FAIL: derive app secrets\n"); g_fail++; free(eng); return; }

    /* ---- Build client Finished and seal under cs_hs. Push to engine RX. ---- */
    {
        uint8_t cfin_vd[32];
        if (tls13_compute_finished(cs_hs, T4, cfin_vd) != 0)
             { printf("  FAIL: cFin compute\n"); g_fail++; free(eng); return; }
        uint8_t cfin_msg[4 + 32];
        int cfin_len = tls13_build_finished(cfin_msg, sizeof(cfin_msg), cfin_vd);
        if (cfin_len <= 0) { printf("  FAIL: cFin build\n"); g_fail++; free(eng); return; }

        tls_record_dir_t cli_write = {0};
        tls13_derive_traffic_keys(cs_hs, cli_write.key, cli_write.static_iv);
        cli_write.seq = 0;

        uint8_t sealed[256];
        size_t sw = tls13_seal_record(&cli_write,
                                      TLS_CT_HANDSHAKE,
                                      TLS_CT_APPLICATION_DATA,
                                      cfin_msg, (size_t)cfin_len,
                                      sealed, sizeof(sealed));
        if (sw == 0) { printf("  FAIL: seal cFin\n"); g_fail++; free(eng); return; }

        /* Drop into engine RX. The engine's RX is empty after consuming
         * the CH, so this should fit. */
        size_t rcap; uint8_t* rrx = pw_tls_rx_buf(eng, &rcap);
        if (sw > rcap) { printf("  FAIL: cFin too big for RX\n"); g_fail++; free(eng); return; }
        memcpy(rrx, sealed, sw); pw_tls_rx_ack(eng, sw);

        int w = pw_tls_step(eng);
        if (w >= 0 && pw_tls_state(eng) == PW_TLS_ST_APP)
             { printf("  PASS: engine transitioned to APP after cFin\n"); g_pass++; }
        else { printf("  FAIL: state=%d phase=%d w=%d\n",
                      pw_tls_state(eng), pw_tls_hs_phase(eng), w);
               g_fail++; free(eng); return; }
    }

    /* ---- Engine should now have read/write keys = app traffic.
     * Verify by independent derive + memcmp (read should be cs_app
     * with seq=0; write should be ss_app with seq=0). ---- */
    {
        uint8_t kref[32], ivref[12];
        tls13_derive_traffic_keys(cs_app, kref, ivref);
        if (memcmp(eng->read.key, kref, 32) == 0
            && memcmp(eng->read.static_iv, ivref, 12) == 0
            && eng->read.seq == 0)
             { printf("  PASS: engine.read = client_app_traffic key, seq=0\n"); g_pass++; }
        else { printf("  FAIL: engine.read mismatch (seq=%llu)\n",
                      (unsigned long long)eng->read.seq); g_fail++; }
        tls13_derive_traffic_keys(ss_app, kref, ivref);
        if (memcmp(eng->write.key, kref, 32) == 0
            && memcmp(eng->write.static_iv, ivref, 12) == 0
            && eng->write.seq == 0)
             { printf("  PASS: engine.write = server_app_traffic key, seq=0\n"); g_pass++; }
        else { printf("  FAIL: engine.write mismatch (seq=%llu)\n",
                      (unsigned long long)eng->write.seq); g_fail++; }
    }

    /* ---- Resumption master secret (RFC 8446 §7.1) check.
     * Recompute externally from `master` + transcript-through-cFin
     * (rebuild the cFin message deterministically from cs_hs+T4) and
     * compare to engine state. ---- */
    {
        uint8_t cfin_vd2[32]; tls13_compute_finished(cs_hs, T4, cfin_vd2);
        uint8_t cfin_msg2[4 + 32];
        int cfin_len2 = tls13_build_finished(cfin_msg2, sizeof(cfin_msg2), cfin_vd2);
        tls13_transcript_update(&cli_ts, cfin_msg2, (size_t)cfin_len2);
        uint8_t T_cf[32];
        tls13_transcript_snapshot(&cli_ts, T_cf);
        uint8_t expected_rms[32];
        if (tls13_compute_resumption_master_secret(master, T_cf, expected_rms) != 0)
             { printf("  FAIL: compute expected RMS\n"); g_fail++; }
        else if (eng->has_rms == 1
                 && memcmp(eng->resumption_master_secret, expected_rms, 32) == 0)
             { printf("  PASS: engine.resumption_master_secret matches\n"); g_pass++; }
        else { printf("  FAIL: RMS mismatch or has_rms=%d\n", eng->has_rms); g_fail++; }
        memset(expected_rms, 0, sizeof(expected_rms));
        memset(T_cf,         0, sizeof(T_cf));
    }

    /* ---- App data roundtrip: encrypt "hello" with cs_app, push,
     * step, drain APP_IN. ---- */
    {
        tls_record_dir_t cli_app_w = {0};
        tls13_derive_traffic_keys(cs_app, cli_app_w.key, cli_app_w.static_iv);
        cli_app_w.seq = 0;

        const char* msg = "hello";
        uint8_t sealed[64];
        size_t sw = tls13_seal_record(&cli_app_w,
                                      TLS_CT_APPLICATION_DATA,
                                      TLS_CT_APPLICATION_DATA,
                                      (const uint8_t*)msg, 5,
                                      sealed, sizeof(sealed));
        if (sw == 0) { printf("  FAIL: seal app\n"); g_fail++; free(eng); return; }

        size_t rcap; uint8_t* rrx = pw_tls_rx_buf(eng, &rcap);
        memcpy(rrx, sealed, sw); pw_tls_rx_ack(eng, sw);

        int w = pw_tls_step(eng);
        if (w < 0) { printf("  FAIL: step app\n"); g_fail++; free(eng); return; }

        size_t app_in_len; const uint8_t* app_in = pw_tls_app_in_buf(eng, &app_in_len);
        if (app_in_len == 5 && memcmp(app_in, "hello", 5) == 0)
             { printf("  PASS: APP_IN surfaces \"hello\" plaintext\n"); g_pass++; }
        else { printf("  FAIL: app_in_len=%zu\n", app_in_len); g_fail++; }
    }

    /* ---- Emit a NewSessionTicket; verify it lands in TX, decrypts
     * cleanly under server app traffic key, parses correctly, and the
     * derived per-ticket PSK matches an independent derivation. ---- */
    {
        /* Snapshot the server write seq + tx buffer length BEFORE
         * the emit. The TX buffer still holds the server handshake
         * flight (the test never tx_ack'd it), so we slice past it
         * to find the new NST record. write.seq was reset to 0 when
         * the engine swapped to app keys after cFin, and no app
         * record has been written by the server yet. */
        size_t tx_before; pw_tls_tx_buf(eng, &tx_before);
        uint64_t srv_seq_before = eng->write.seq;

        const uint8_t nonce[8] = { 1,2,3,4,5,6,7,8 };
        const uint8_t tid[16]  = { 0xa,0xb,0xc,0xd,0xe,0xf,0x10,0x11,
                                   0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19 };
        uint8_t derived_psk[32];
        if (pw_tls_engine_emit_session_ticket(eng, 7200, 0xdeadbeef,
                                              nonce, sizeof(nonce),
                                              tid,   sizeof(tid),
                                              derived_psk) != 0)
             { printf("  FAIL: emit_session_ticket\n"); g_fail++; free(eng); return; }
        printf("  PASS: pw_tls_engine_emit_session_ticket OK\n"); g_pass++;

        /* PSK independent recompute. */
        uint8_t expect_psk[32];
        if (tls13_derive_resumption_psk(eng->resumption_master_secret,
                                        nonce, sizeof(nonce),
                                        expect_psk) == 0
            && memcmp(derived_psk, expect_psk, 32) == 0)
             { printf("  PASS: per-ticket PSK matches independent HKDF\n"); g_pass++; }
        else { printf("  FAIL: PSK mismatch\n"); g_fail++; }
        memset(expect_psk, 0, sizeof(expect_psk));

        /* Pull the freshly-sealed record out of TX (it's the only new
         * thing there since srv_seq_before was 0). */
        size_t txlen; const uint8_t* tx_all = pw_tls_tx_buf(eng, &txlen);
        if (txlen <= tx_before) { printf("  FAIL: TX did not grow\n"); g_fail++; free(eng); return; }
        const uint8_t* tx_nst = tx_all + tx_before;
        size_t nst_tx_len = txlen - tx_before;
        if (nst_tx_len < TLS13_RECORD_HEADER_LEN) { printf("  FAIL: NST too short %zu\n", nst_tx_len); g_fail++; free(eng); return; }
        uint16_t reclen = ((uint16_t)tx_nst[3] << 8) | tx_nst[4];
        size_t rec_total = TLS13_RECORD_HEADER_LEN + reclen;
        if (rec_total != nst_tx_len) { printf("  FAIL: NST tx_len mismatch (rec=%zu tx=%zu)\n", rec_total, nst_tx_len); g_fail++; free(eng); return; }

        tls_record_dir_t cli_nst_read = {0};
        tls13_derive_traffic_keys(ss_app, cli_nst_read.key, cli_nst_read.static_iv);
        cli_nst_read.seq = srv_seq_before;

        /* tls13_open_record mutates the buffer in place — copy it. */
        uint8_t copy[1024];
        if (rec_total > sizeof(copy)) { printf("  FAIL: NST too big\n"); g_fail++; free(eng); return; }
        memcpy(copy, tx_nst, rec_total);
        tls_content_type_t inner = TLS_CT_INVALID;
        uint8_t* pt = NULL; size_t pt_len = 0;
        if (tls13_open_record(&cli_nst_read, copy, rec_total, &inner, &pt, &pt_len) != 0)
             { printf("  FAIL: client cannot decrypt NST\n"); g_fail++; free(eng); return; }
        if (inner != TLS_CT_HANDSHAKE) { printf("  FAIL: NST inner=%d (want HS)\n", inner); g_fail++; free(eng); return; }

        /* Parse NST: type 0x04, len, lifetime, age_add, nonce, ticket, exts. */
        if (pt_len < 4 + 13 + 2)        { printf("  FAIL: NST too short %zu\n", pt_len); g_fail++; free(eng); return; }
        if (pt[0] != 0x04)              { printf("  FAIL: NST type=%02x\n", pt[0]); g_fail++; free(eng); return; }
        uint32_t body_len = ((uint32_t)pt[1] << 16) | ((uint32_t)pt[2] << 8) | pt[3];
        if ((size_t)body_len + 4 != pt_len) { printf("  FAIL: NST body_len mismatch\n"); g_fail++; free(eng); return; }
        const uint8_t* q = pt + 4;
        uint32_t lifetime = ((uint32_t)q[0]<<24)|((uint32_t)q[1]<<16)|((uint32_t)q[2]<<8)|q[3]; q += 4;
        uint32_t aa       = ((uint32_t)q[0]<<24)|((uint32_t)q[1]<<16)|((uint32_t)q[2]<<8)|q[3]; q += 4;
        uint8_t  nl = *q++;
        if (lifetime == 7200 && aa == 0xdeadbeef && nl == sizeof(nonce)
            && memcmp(q, nonce, sizeof(nonce)) == 0)
             { printf("  PASS: NST lifetime/age_add/nonce parse OK\n"); g_pass++; }
        else { printf("  FAIL: NST hdr fields lifetime=%u aa=%08x nl=%u\n",
                      lifetime, aa, nl); g_fail++; }
        q += nl;
        uint16_t il = ((uint16_t)q[0] << 8) | q[1]; q += 2;
        if (il == sizeof(tid) && memcmp(q, tid, sizeof(tid)) == 0)
             { printf("  PASS: NST ticket_id roundtrip\n"); g_pass++; }
        else { printf("  FAIL: NST ticket_id mismatch (len=%u)\n", il); g_fail++; }
        q += il;
        uint16_t exts = ((uint16_t)q[0] << 8) | q[1];
        if (exts == 0) { printf("  PASS: NST extensions empty\n"); g_pass++; }
        else           { printf("  FAIL: NST exts=%u\n", exts); g_fail++; }

        memset(derived_psk, 0, sizeof(derived_psk));
    }

    /* ---- Handshake secrets must have been wiped. ---- */
    {
        uint8_t zero[32] = {0};
        if (memcmp(eng->handshake_secret, zero, 32) == 0
            && memcmp(eng->cs_handshake_secret, zero, 32) == 0
            && memcmp(eng->ss_handshake_secret, zero, 32) == 0)
             { printf("  PASS: handshake-phase secrets wiped\n"); g_pass++; }
        else { printf("  FAIL: handshake secrets not wiped\n"); g_fail++; }
    }

    free(eng);
}

/* ============================================================
 *  Tolerance test variant: CCS in one rx_ack, then cFin in a second.
 *  This exercises the "step returns WANT_RX after CCS, then we get
 *  more bytes" path that's hidden in the bundled-ack version.
 * ============================================================ */
static void test_engine_tolerates_dummy_ccs_split(void) {
    printf("== TLS engine: tolerates dummy CCS (split from cFin) ==\n");

    uint8_t srv_seed[32];  for (int i = 0; i < 32; i++) srv_seed[i] = 0x60 + (uint8_t)i;
    uint8_t srv_pub[32];   ed25519_pubkey_from_seed(srv_pub, srv_seed);
    const uint8_t fake_cert[16] = { 0x30, 0x0e, 0x05, 0x00 };
    const uint8_t* cert_chain = fake_cert;
    size_t         cert_lens[1]  = { sizeof(fake_cert) };

    uint8_t cli_priv[32];  for (int i = 0; i < 32; i++) cli_priv[i] = 0x33 ^ (uint8_t)i;
    cli_priv[0] &= 248; cli_priv[31] &= 127; cli_priv[31] |= 64;
    uint8_t cli_pub[32];   x25519(cli_pub, cli_priv, X25519_BASE_POINT);

    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    test_rng_state_t rng_st = { .next = 0 };
    pw_tls_engine_configure_server(eng, test_rng, &rng_st, srv_seed,
                                   cert_chain, cert_lens, 1);

    uint8_t srv_eph_priv[32];
    {
        test_rng_state_t r = { .next = 0 };
        uint8_t scratch[32];
        test_rng(&r, scratch, 32);
        test_rng(&r, srv_eph_priv, 32);
        srv_eph_priv[0] &= 248; srv_eph_priv[31] &= 127; srv_eph_priv[31] |= 64;
    }
    uint8_t srv_pub_eph[32]; x25519(srv_pub_eph, srv_eph_priv, X25519_BASE_POINT);
    uint8_t shared[32];      x25519(shared, cli_priv, srv_pub_eph);

    uint8_t ch_rec[2048];
    uint8_t sid[32]; for (int i = 0; i < 32; i++) sid[i] = (uint8_t)i;
    size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec), cli_pub, sid, 32,
                                          "h.example", 1, 1);
    size_t cap; uint8_t* rxb = pw_tls_rx_buf(eng, &cap);
    memcpy(rxb, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);
    pw_tls_step(eng);

    /* Replay client-side transcript & derive keys (same as bundled
     * test). */
    size_t tx_len; const uint8_t* tx = pw_tls_tx_buf(eng, &tx_len);
    uint16_t sh_body = ((uint16_t)tx[3] << 8) | tx[4];
    tls13_transcript_t cts;
    tls13_transcript_init(&cts);
    tls13_transcript_update(&cts, ch_rec + 5, ch_len - 5);
    tls13_transcript_update(&cts, tx + 5, sh_body);

    uint8_t T1[32]; tls13_transcript_snapshot(&cts, T1);
    uint8_t hs[32], cs_hs[32], ss_hs[32];
    tls13_compute_handshake_secrets(shared, T1, hs, cs_hs, ss_hs);

    tls_record_dir_t cli_r = {0};
    tls13_derive_traffic_keys(ss_hs, cli_r.key, cli_r.static_iv);
    size_t off = 5 + sh_body;
    while (off + 5 <= tx_len) {
        uint16_t rl = ((uint16_t)tx[off+3] << 8) | tx[off+4];
        uint8_t scr[2048]; memcpy(scr, tx + off, 5 + rl);
        tls_content_type_t inner; uint8_t* pt; size_t pl;
        tls13_open_record(&cli_r, scr, 5 + rl, &inner, &pt, &pl);
        tls13_transcript_update(&cts, pt, pl);
        off += 5 + rl;
    }

    uint8_t T4[32]; tls13_transcript_snapshot(&cts, T4);

    /* ---- Push only the dummy CCS first. ---- */
    static const uint8_t dummy_ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    {
        size_t rcap; uint8_t* rrx = pw_tls_rx_buf(eng, &rcap);
        memcpy(rrx, dummy_ccs, 6); pw_tls_rx_ack(eng, 6);
    }
    pw_tls_step(eng);
    if (pw_tls_state(eng) == PW_TLS_ST_HANDSHAKE
        && pw_tls_hs_phase(eng) == PW_TLS_HS_AFTER_SF_AWAIT_CF)
         { printf("  PASS: CCS-only step stays in AFTER_SF_AWAIT_CF\n"); g_pass++; }
    else { printf("  FAIL: state=%d phase=%d after CCS-only\n",
                  pw_tls_state(eng), pw_tls_hs_phase(eng)); g_fail++; free(eng); return; }

    /* ---- Now push the cFin. ---- */
    uint8_t cfin_vd[32]; tls13_compute_finished(cs_hs, T4, cfin_vd);
    uint8_t cfin_msg[36]; int cfin_len = tls13_build_finished(cfin_msg, sizeof(cfin_msg), cfin_vd);
    tls_record_dir_t cli_w = {0};
    tls13_derive_traffic_keys(cs_hs, cli_w.key, cli_w.static_iv);
    uint8_t sealed[128];
    size_t sw = tls13_seal_record(&cli_w, TLS_CT_HANDSHAKE, TLS_CT_APPLICATION_DATA,
                                  cfin_msg, (size_t)cfin_len, sealed, sizeof(sealed));
    {
        size_t rcap; uint8_t* rrx = pw_tls_rx_buf(eng, &rcap);
        memcpy(rrx, sealed, sw); pw_tls_rx_ack(eng, sw);
    }
    pw_tls_step(eng);
    if (pw_tls_state(eng) == PW_TLS_ST_APP)
         { printf("  PASS: engine transitions to APP after split CCS+cFin\n"); g_pass++; }
    else { printf("  FAIL: state=%d after cFin (split)\n", pw_tls_state(eng)); g_fail++; }

    free(eng);
}

/* ============================================================
 *  After fatal handshake error, the engine MUST NOT expose any
 *  partial bytes via pw_tls_tx_buf() and MUST have wiped its
 *  installed record-layer keys. Driven by a hostile cFin (random
 *  verify_data) — the engine has the encrypted server flight in TX
 *  by the time it tries to verify the cFin, so this exercises the
 *  half-emitted-flight rollback path AND the keys-wiped path.
 * ============================================================ */
static void test_engine_fatal_wipes_tx_and_keys(void) {
    printf("== TLS engine: fatal handshake wipes TX + keys ==\n");

    uint8_t srv_seed[32];  for (int i = 0; i < 32; i++) srv_seed[i] = 0xb0 + (uint8_t)i;
    const uint8_t fake_cert[16] = { 0x30, 0x0e, 0x05, 0x00 };
    const uint8_t* cert_chain = fake_cert;
    size_t         cert_lens[1]  = { sizeof(fake_cert) };

    uint8_t cli_priv[32];  for (int i = 0; i < 32; i++) cli_priv[i] = 0x21 ^ (uint8_t)i;
    cli_priv[0] &= 248; cli_priv[31] &= 127; cli_priv[31] |= 64;
    uint8_t cli_pub[32];   x25519(cli_pub, cli_priv, X25519_BASE_POINT);

    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    test_rng_state_t rng_st = { .next = 0 };
    pw_tls_engine_configure_server(eng, test_rng, &rng_st, srv_seed,
                                   cert_chain, cert_lens, 1);

    /* Drive CH -> AFTER_SF_AWAIT_CF (server flight already in TX). */
    uint8_t ch_rec[2048];
    uint8_t sid[32]; for (int i = 0; i < 32; i++) sid[i] = (uint8_t)i;
    size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec), cli_pub, sid, 32,
                                          "h.example", 1, 1);
    size_t cap; uint8_t* rxb = pw_tls_rx_buf(eng, &cap);
    memcpy(rxb, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);
    pw_tls_step(eng);

    /* Sanity: TX is non-empty (SH + 4 encrypted records) and the
     * engine has handshake-traffic keys installed. */
    size_t tx_len; const uint8_t* tx = pw_tls_tx_buf(eng, &tx_len);
    if (tx_len > 0 && eng->keys_installed)
         { printf("  PASS: pre-fail TX non-empty + keys installed\n"); g_pass++; }
    else { printf("  FAIL: pre-fail tx_len=%zu keys=%d\n",
                  tx_len, eng->keys_installed); g_fail++; free(eng); return; }
    (void)tx;

    /* Now derive the CORRECT cs_hs key but build a Finished message
     * with a DELIBERATELY WRONG verify_data. The engine should decrypt
     * the record (so AEAD tag is fine), parse the Finished header,
     * but fail tls13_verify_finished and go FAILED. */
    uint16_t sh_body = ((uint16_t)tx[3] << 8) | tx[4];
    const uint8_t* sh_msg = tx + 5;
    tls13_transcript_t cts;
    tls13_transcript_init(&cts);
    tls13_transcript_update(&cts, ch_rec + 5, ch_len - 5);
    tls13_transcript_update(&cts, sh_msg, sh_body);

    /* Compute shared via expected server eph priv. */
    uint8_t srv_eph_priv[32];
    {
        test_rng_state_t r = { .next = 0 };
        uint8_t scratch[32]; test_rng(&r, scratch, 32);
        test_rng(&r, srv_eph_priv, 32);
        srv_eph_priv[0] &= 248; srv_eph_priv[31] &= 127; srv_eph_priv[31] |= 64;
    }
    uint8_t srv_pub_eph[32]; x25519(srv_pub_eph, srv_eph_priv, X25519_BASE_POINT);
    uint8_t shared[32]; x25519(shared, cli_priv, srv_pub_eph);

    uint8_t T1[32]; tls13_transcript_snapshot(&cts, T1);
    uint8_t hs[32], cs_hs[32], ss_hs[32];
    tls13_compute_handshake_secrets(shared, T1, hs, cs_hs, ss_hs);

    /* Build a cFin with garbage verify_data. */
    uint8_t bad_vd[32]; for (int i = 0; i < 32; i++) bad_vd[i] = 0xee;
    uint8_t cfin_msg[36]; int cfin_len = tls13_build_finished(cfin_msg, sizeof(cfin_msg), bad_vd);
    tls_record_dir_t cli_w = {0};
    tls13_derive_traffic_keys(cs_hs, cli_w.key, cli_w.static_iv);
    uint8_t sealed[128];
    size_t sw = tls13_seal_record(&cli_w, TLS_CT_HANDSHAKE, TLS_CT_APPLICATION_DATA,
                                  cfin_msg, (size_t)cfin_len, sealed, sizeof(sealed));

    size_t rcap; uint8_t* rrx = pw_tls_rx_buf(eng, &rcap);
    memcpy(rrx, sealed, sw); pw_tls_rx_ack(eng, sw);
    int rc = pw_tls_step(eng);

    if (rc < 0 && pw_tls_state(eng) == PW_TLS_ST_FAILED)
         { printf("  PASS: bad cFin moves engine to FAILED\n"); g_pass++; }
    else { printf("  FAIL: rc=%d state=%d\n", rc, pw_tls_state(eng)); g_fail++; free(eng); return; }

    if (pw_tls_last_error(eng) == PW_TLS_ERR_AUTH)
         { printf("  PASS: last_error == AUTH for bad cFin\n"); g_pass++; }
    else { printf("  FAIL: last_error=%d (want AUTH=%d)\n",
                  pw_tls_last_error(eng), PW_TLS_ERR_AUTH); g_fail++; }

    size_t tx2; (void)pw_tls_tx_buf(eng, &tx2);
    if (tx2 == 0)
         { printf("  PASS: TX cleared after fatal handshake failure\n"); g_pass++; }
    else { printf("  FAIL: tx_len=%zu (should be 0)\n", tx2); g_fail++; }

    {
        uint8_t zero32[32] = {0}, zero12[12] = {0};
        int wiped = (memcmp(eng->read.key, zero32, 32) == 0)
                 && (memcmp(eng->read.static_iv, zero12, 12) == 0)
                 && (memcmp(eng->write.key, zero32, 32) == 0)
                 && (memcmp(eng->write.static_iv, zero12, 12) == 0)
                 && (eng->keys_installed == 0);
        if (wiped) { printf("  PASS: record-layer keys wiped on fatal\n"); g_pass++; }
        else       { printf("  FAIL: keys_installed=%d\n", eng->keys_installed); g_fail++; }
    }

    free(eng);
}

/* PROTOCOL-class error: feed the engine a record with a bogus
 * legacy_record_version high byte (must be 0x03). The CH parser
 * rejects it before any cipher work. last_error must be PROTOCOL,
 * not AUTH (no AEAD ran), and not INTERNAL. */
static void test_engine_last_error_protocol(void) {
    printf("== TLS engine: malformed record -> PROTOCOL error ==\n");

    uint8_t srv_seed[32]; for (int i = 0; i < 32; i++) srv_seed[i] = 0x33 + (uint8_t)i;
    const uint8_t fake_cert[16] = { 0x30, 0x0e, 0x05, 0x00 };
    const uint8_t* cert_chain = fake_cert;
    size_t cert_lens[1] = { sizeof(fake_cert) };

    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    test_rng_state_t rng_st = { .next = 0 };
    pw_tls_engine_configure_server(eng, test_rng, &rng_st, srv_seed,
                                   cert_chain, cert_lens, 1);

    /* Minimum-length malformed record: type=22 OK, version high byte
     * = 0xFF (invalid), length=4, garbage body. */
    uint8_t bad_rec[5 + 4] = { 0x16, 0xFF, 0x03, 0x00, 0x04, 0,0,0,0 };
    size_t cap; uint8_t* rxb = pw_tls_rx_buf(eng, &cap);
    memcpy(rxb, bad_rec, sizeof(bad_rec));
    pw_tls_rx_ack(eng, sizeof(bad_rec));
    int rc = pw_tls_step(eng);

    if (rc < 0 && pw_tls_state(eng) == PW_TLS_ST_FAILED)
         { printf("  PASS: malformed CH moves engine to FAILED\n"); g_pass++; }
    else { printf("  FAIL: rc=%d state=%d\n", rc, pw_tls_state(eng)); g_fail++; free(eng); return; }

    if (pw_tls_last_error(eng) == PW_TLS_ERR_PROTOCOL)
         { printf("  PASS: last_error == PROTOCOL for malformed record\n"); g_pass++; }
    else { printf("  FAIL: last_error=%d (want PROTOCOL=%d)\n",
                  pw_tls_last_error(eng), PW_TLS_ERR_PROTOCOL); g_fail++; }

    free(eng);
}

/* Init-time invariant: a freshly initialised engine reports
 * PW_TLS_ERR_NONE. NULL engine reports INTERNAL (defensive). */
static void test_engine_last_error_init(void) {
    printf("== TLS engine: last_error init invariants ==\n");
    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    if (pw_tls_last_error(eng) == PW_TLS_ERR_NONE)
         { printf("  PASS: fresh engine -> ERR_NONE\n"); g_pass++; }
    else { printf("  FAIL: %d\n", pw_tls_last_error(eng)); g_fail++; }
    if (pw_tls_last_error(NULL) == PW_TLS_ERR_INTERNAL)
         { printf("  PASS: NULL engine -> ERR_INTERNAL\n"); g_pass++; }
    else { printf("  FAIL: NULL gave %d\n", pw_tls_last_error(NULL)); g_fail++; }
    free(eng);
}

/* mbuf-tls-record sizing: PW_RX_REASSEMBLY_SLOT must be at least
 * large enough to hold one wire-format TLS 1.3 record (5 byte
 * header + max ciphertext). Compile-time + runtime check so any
 * future change to either constant trips loudly. */
static void test_pw_rx_reassembly_slot_sizing(void) {
    printf("== mbuf-tls-record: PW_RX_REASSEMBLY_SLOT sizing ==\n");
    if (PW_RX_REASSEMBLY_SLOT >= TLS13_RECORD_HEADER_LEN + TLS13_MAX_CIPHERTEXT)
         { printf("  PASS: slot=%u >= header+max_ct=%u\n",
                  (unsigned)PW_RX_REASSEMBLY_SLOT,
                  (unsigned)(TLS13_RECORD_HEADER_LEN + TLS13_MAX_CIPHERTEXT));
           g_pass++; }
    else { printf("  FAIL: slot=%u < %u\n",
                  (unsigned)PW_RX_REASSEMBLY_SLOT,
                  (unsigned)(TLS13_RECORD_HEADER_LEN + TLS13_MAX_CIPHERTEXT));
           g_fail++; }

    /* Engine internal buffers must match the wire-record cap so a
     * wire record fits straight into rx_buf without secondary
     * staging. (PW_TLS_BUF_CAP is in engine.h.) */
    if ((size_t)PW_RX_REASSEMBLY_SLOT == (size_t)PW_TLS_BUF_CAP)
         { printf("  PASS: PW_RX_REASSEMBLY_SLOT == PW_TLS_BUF_CAP (%u)\n",
                  (unsigned)PW_TLS_BUF_CAP); g_pass++; }
    else { printf("  FAIL: %u vs %u\n",
                  (unsigned)PW_RX_REASSEMBLY_SLOT, (unsigned)PW_TLS_BUF_CAP);
           g_fail++; }
}

/* ============================================================
 *  Tolerance test for RFC 8446 §D.4 dummy ChangeCipherSpec.
 *
 *  Real TLS 1.3 clients in compatibility mode emit
 *      14 03 03 00 01 01
 *  between their CH and their encrypted Finished. The engine must
 *  silently drop these and still process the cFin that follows.
 * ============================================================ */
static void test_engine_tolerates_dummy_ccs(void) {
    printf("== TLS engine: tolerates dummy ChangeCipherSpec ==\n");

    /* Setup mirrors the roundtrip test, but condensed. */
    uint8_t srv_seed[32];  for (int i = 0; i < 32; i++) srv_seed[i] = 0x10 + (uint8_t)i;
    uint8_t srv_pub[32];   ed25519_pubkey_from_seed(srv_pub, srv_seed);
    const uint8_t fake_cert[16] = { 0x30, 0x0e, 0x05, 0x00 };
    const uint8_t* cert_chain = fake_cert;
    size_t         cert_lens[1]  = { sizeof(fake_cert) };

    uint8_t cli_priv[32];  for (int i = 0; i < 32; i++) cli_priv[i] = 0x55 ^ (uint8_t)i;
    cli_priv[0] &= 248; cli_priv[31] &= 127; cli_priv[31] |= 64;
    uint8_t cli_pub[32];   x25519(cli_pub, cli_priv, X25519_BASE_POINT);

    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    test_rng_state_t rng_st = { .next = 0 };
    pw_tls_engine_configure_server(eng, test_rng, &rng_st, srv_seed,
                                   cert_chain, cert_lens, 1);

    uint8_t srv_eph_priv[32];
    {
        test_rng_state_t r = { .next = 0 };
        uint8_t scratch[32];
        test_rng(&r, scratch, 32);            /* server_random */
        test_rng(&r, srv_eph_priv, 32);
        srv_eph_priv[0] &= 248; srv_eph_priv[31] &= 127; srv_eph_priv[31] |= 64;
    }
    uint8_t srv_pub_eph[32]; x25519(srv_pub_eph, srv_eph_priv, X25519_BASE_POINT);
    uint8_t shared[32];      x25519(shared, cli_priv, srv_pub_eph);

    uint8_t ch_rec[2048];
    uint8_t sid[32]; for (int i = 0; i < 32; i++) sid[i] = (uint8_t)i;
    size_t  ch_len = build_test_ch_record(ch_rec, sizeof(ch_rec), cli_pub, sid, 32,
                                          "h.example", 1, 1);
    size_t cap; uint8_t* rxb = pw_tls_rx_buf(eng, &cap);
    memcpy(rxb, ch_rec, ch_len); pw_tls_rx_ack(eng, ch_len);
    pw_tls_step(eng);

    if (pw_tls_hs_phase(eng) != PW_TLS_HS_AFTER_SF_AWAIT_CF)
         { printf("  FAIL: did not reach AFTER_SF_AWAIT_CF\n"); g_fail++; free(eng); return; }

    /* Replay client transcript & derive keys. */
    size_t tx_len; const uint8_t* tx = pw_tls_tx_buf(eng, &tx_len);
    uint16_t sh_body = ((uint16_t)tx[3] << 8) | tx[4];
    tls13_transcript_t cts;
    tls13_transcript_init(&cts);
    tls13_transcript_update(&cts, ch_rec + 5, ch_len - 5);
    tls13_transcript_update(&cts, tx + 5, sh_body);

    uint8_t T1[32]; tls13_transcript_snapshot(&cts, T1);
    uint8_t hs[32], cs_hs[32], ss_hs[32];
    tls13_compute_handshake_secrets(shared, T1, hs, cs_hs, ss_hs);

    /* Decrypt server's encrypted flight to update transcript. */
    tls_record_dir_t cli_r = {0};
    tls13_derive_traffic_keys(ss_hs, cli_r.key, cli_r.static_iv);
    size_t off = 5 + sh_body;
    while (off + 5 <= tx_len) {
        uint16_t rl = ((uint16_t)tx[off+3] << 8) | tx[off+4];
        uint8_t scr[2048]; memcpy(scr, tx + off, 5 + rl);
        tls_content_type_t inner; uint8_t* pt; size_t pl;
        tls13_open_record(&cli_r, scr, 5 + rl, &inner, &pt, &pl);
        tls13_transcript_update(&cts, pt, pl);
        off += 5 + rl;
    }

    uint8_t T4[32]; tls13_transcript_snapshot(&cts, T4);

    /* Build cFin. */
    uint8_t cfin_vd[32]; tls13_compute_finished(cs_hs, T4, cfin_vd);
    uint8_t cfin_msg[36]; int cfin_len = tls13_build_finished(cfin_msg, sizeof(cfin_msg), cfin_vd);
    tls_record_dir_t cli_w = {0};
    tls13_derive_traffic_keys(cs_hs, cli_w.key, cli_w.static_iv);
    uint8_t sealed[128];
    size_t sw = tls13_seal_record(&cli_w, TLS_CT_HANDSHAKE, TLS_CT_APPLICATION_DATA,
                                  cfin_msg, (size_t)cfin_len, sealed, sizeof(sealed));

    /* Push CCS THEN cFin into RX in one ack. */
    static const uint8_t dummy_ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    size_t rcap; uint8_t* rrx = pw_tls_rx_buf(eng, &rcap);
    memcpy(rrx,           dummy_ccs, 6);
    memcpy(rrx + 6,       sealed,    sw);
    pw_tls_rx_ack(eng, 6 + sw);

    pw_tls_step(eng);
    if (pw_tls_state(eng) == PW_TLS_ST_APP)
         { printf("  PASS: engine consumed CCS + processed cFin\n"); g_pass++; }
    else { printf("  FAIL: state=%d after CCS+cFin\n", pw_tls_state(eng)); g_fail++; }

    free(eng);
}

/* ---------- engine pool (rent / release) ---------- */

#include "../tls/engine_pool.h"

static void test_engine_pool(void) {
    printf("== engine pool (rent / release / scrub) ==\n");

    /* 4 slots is enough to exercise exhaustion + reuse without
     * blowing the stack (engine is ~64 KiB, so 4 * 64 = 256 KiB). */
    enum { N = 4 };
    static uint8_t storage[PW_TLS_ENGINE_POOL_BYTES(N)];
    pw_tls_engine_pool_t pool;
    int rc = pw_tls_engine_pool_init(&pool, storage, N);
    if (rc == 0 && pw_tls_engine_pool_capacity(&pool) == N
                && pw_tls_engine_pool_in_use(&pool) == 0)
         { printf("  PASS: pool init capacity=%u\n", N); g_pass++; }
    else { printf("  FAIL: pool init rc=%d\n", rc); g_fail++; }

    /* Acquire all N slots. */
    pw_tls_engine_t* es[N] = {0};
    int all_ok = 1;
    for (int i = 0; i < N; i++) {
        es[i] = pw_tls_engine_pool_acquire(&pool);
        if (!es[i]) { all_ok = 0; break; }
        /* Engine must be in the post-init state. */
        if (pw_tls_state(es[i]) != PW_TLS_ST_HANDSHAKE) { all_ok = 0; break; }
        if (es[i]->records_in != 0 || es[i]->records_out != 0) { all_ok = 0; break; }
    }
    if (all_ok && pw_tls_engine_pool_in_use(&pool) == N
               && pw_tls_engine_pool_high_water(&pool) == N)
         { printf("  PASS: acquired %d clean engines (in_use=%u hwm=%u)\n",
                  N, pw_tls_engine_pool_in_use(&pool),
                  pw_tls_engine_pool_high_water(&pool)); g_pass++; }
    else { printf("  FAIL: acquire-N\n"); g_fail++; }

    /* Pool exhausted now: next acquire must NULL + bump exhaustion. */
    uint64_t exh_before = pw_tls_engine_pool_exhaustion(&pool);
    pw_tls_engine_t* over = pw_tls_engine_pool_acquire(&pool);
    if (over == NULL && pw_tls_engine_pool_exhaustion(&pool) == exh_before + 1)
         { printf("  PASS: exhaustion returns NULL + bumps counter\n"); g_pass++; }
    else { printf("  FAIL: exhaustion behaviour\n"); g_fail++; }

    /* Stash some "key material" in es[2] so we can verify scrub. */
    for (size_t i = 0; i < sizeof(es[2]->cs_app_traffic_secret); i++) {
        es[2]->cs_app_traffic_secret[i] = (uint8_t)(0xA0 + i);
    }
    es[2]->records_in = 0xdeadbeefULL;
    es[2]->state = PW_TLS_ST_APP;
    es[2]->keys_installed = 1;

    /* Snapshot the slot address so we can assert the scrub on the
     * SAME memory after release. (Pool may hand the same slot back
     * on next acquire — LIFO free list.) */
    pw_tls_engine_t* slot_addr = es[2];

    pw_tls_engine_pool_release(&pool, es[2]);
    es[2] = NULL;

    /* The slot's first 4 bytes now hold a free-list pointer (set by
     * pool_release) — that's where `state` happens to live, so we
     * don't check `state` here. Every OTHER byte must be zero, in
     * particular all key material and counters. */
    int scrubbed = 1;
    for (size_t i = 0; i < sizeof(slot_addr->cs_app_traffic_secret); i++) {
        if (slot_addr->cs_app_traffic_secret[i] != 0) { scrubbed = 0; break; }
    }
    if (slot_addr->records_in != 0)     scrubbed = 0;
    if (slot_addr->keys_installed != 0) scrubbed = 0;
    if (scrubbed && pw_tls_engine_pool_in_use(&pool) == N - 1)
         { printf("  PASS: release scrubs key material + counters (in_use=%u)\n",
                  pw_tls_engine_pool_in_use(&pool)); g_pass++; }
    else { printf("  FAIL: release scrub\n"); g_fail++; }

    /* Reacquire — should reuse the just-released slot (LIFO) and
     * present a clean engine again. */
    pw_tls_engine_t* re = pw_tls_engine_pool_acquire(&pool);
    if (re == slot_addr
        && pw_tls_state(re) == PW_TLS_ST_HANDSHAKE
        && re->records_in == 0
        && re->keys_installed == 0)
         { printf("  PASS: reacquired same slot, clean state\n"); g_pass++; }
    else { printf("  FAIL: reacquire (re=%p slot=%p state=%d)\n",
                  (void*)re, (void*)slot_addr,
                  re ? (int)pw_tls_state(re) : -1); g_fail++; }
    es[2] = re;

    /* Release everything; in_use must drop to zero. */
    for (int i = 0; i < N; i++) {
        if (es[i]) pw_tls_engine_pool_release(&pool, es[i]);
    }
    if (pw_tls_engine_pool_in_use(&pool) == 0
        && pw_tls_engine_pool_high_water(&pool) == N)
         { printf("  PASS: drained pool, hwm preserved (rents=%llu)\n",
                  (unsigned long long)pw_tls_engine_pool_rents(&pool));
           g_pass++; }
    else { printf("  FAIL: drain (in_use=%u)\n",
                  pw_tls_engine_pool_in_use(&pool)); g_fail++; }

    /* NULL safety. */
    pw_tls_engine_pool_release(&pool, NULL);
    if (pw_tls_engine_pool_in_use(&pool) == 0)
         { printf("  PASS: release(NULL) is a no-op\n"); g_pass++; }
    else { printf("  FAIL: release(NULL) corrupted in_use\n"); g_fail++; }
}

/* ---------- TLS ticket store + early-secret schedule ---------- */

static void test_tls_ticket_store(void) {
    printf("== TLS ticket store (insert / lookup / consume / evict) ==\n");
    pw_tls_ticket_store_t s;
    pw_tls_ticket_store_init(&s);

    uint8_t id1[8] = {1,1,1,1,1,1,1,1};
    uint8_t id2[8] = {2,2,2,2,2,2,2,2};
    uint8_t psk[32]; memset(psk, 0xAA, 32);

    if (pw_tls_ticket_store_insert(&s, id1, 8, psk, 0xdeadbeef, 7200, 1000, 0) == 0)
         { printf("  PASS: insert id1\n"); g_pass++; }
    else { printf("  FAIL: insert id1\n"); g_fail++; }

    pw_tls_ticket_t* t = pw_tls_ticket_store_lookup(&s, id1, 8, 1500);
    if (t && t->age_add == 0xdeadbeef && memcmp(t->psk, psk, 32) == 0)
         { printf("  PASS: lookup id1 returns inserted ticket\n"); g_pass++; }
    else { printf("  FAIL: lookup id1\n"); g_fail++; return; }

    if (!pw_tls_ticket_store_lookup(&s, id2, 8, 1500))
         { printf("  PASS: lookup unknown returns NULL\n"); g_pass++; }
    else { printf("  FAIL: lookup unknown\n"); g_fail++; }

    /* Expiry: lifetime 7200s -> exp = 1000 + 7_200_000 = 7_201_000 ms. */
    if (!pw_tls_ticket_store_lookup(&s, id1, 8, 7202000))
         { printf("  PASS: expired lookup returns NULL + invalidates\n"); g_pass++; }
    else { printf("  FAIL: expired lookup returned a ticket\n"); g_fail++; }
    if (!pw_tls_ticket_store_lookup(&s, id1, 8, 1500))
         { printf("  PASS: previously-expired ticket fully invalidated\n"); g_pass++; }
    else { printf("  FAIL: invalidate did not stick\n"); g_fail++; }

    /* Reinsert + 0-RTT consume. */
    pw_tls_ticket_store_insert(&s, id1, 8, psk, 0, 7200, 1000, 16384);
    pw_tls_ticket_t* tt = pw_tls_ticket_store_lookup(&s, id1, 8, 1500);
    if (tt && pw_tls_ticket_can_early_data(tt) == 1)
         { printf("  PASS: fresh ticket allows early data\n"); g_pass++; }
    else { printf("  FAIL: fresh ticket disallows early data\n"); g_fail++; }
    if (pw_tls_ticket_consume_for_0rtt(tt) == 0)
         { printf("  PASS: first consume_for_0rtt OK\n"); g_pass++; }
    else { printf("  FAIL: first consume\n"); g_fail++; }
    if (pw_tls_ticket_consume_for_0rtt(tt) == -1
        && pw_tls_ticket_can_early_data(tt) == 0)
         { printf("  PASS: second consume rejected; 0-RTT now disabled\n"); g_pass++; }
    else { printf("  FAIL: replay defense did not engage\n"); g_fail++; }

    /* Eviction: fill all PW_TLS_TICKET_SLOTS-1 more slots, then one
     * extra forces eviction of the oldest. */
    pw_tls_ticket_store_init(&s);
    for (unsigned i = 0; i < PW_TLS_TICKET_SLOTS; i++) {
        uint8_t id[2] = { (uint8_t)(0xC0 + i), (uint8_t)i };
        pw_tls_ticket_store_insert(&s, id, 2, psk, 0, 7200,
                                   /* issued_at: ascending */ 100ULL + i, 0);
    }
    /* All 16 should be present. */
    int found_all = 1;
    for (unsigned i = 0; i < PW_TLS_TICKET_SLOTS; i++) {
        uint8_t id[2] = { (uint8_t)(0xC0 + i), (uint8_t)i };
        if (!pw_tls_ticket_store_lookup(&s, id, 2, 200)) { found_all = 0; break; }
    }
    if (found_all) { printf("  PASS: store full, all 16 lookups OK\n"); g_pass++; }
    else           { printf("  FAIL: not all 16 found\n"); g_fail++; }

    /* Insert one more — the OLDEST (index 0, issued_at=100) gets evicted. */
    uint8_t id_new[2] = { 0xFF, 0xFF };
    pw_tls_ticket_store_insert(&s, id_new, 2, psk, 0, 7200, 9999, 0);
    uint8_t id_old[2] = { 0xC0, 0x00 };
    if (!pw_tls_ticket_store_lookup(&s, id_old, 2, 200)
        &&  pw_tls_ticket_store_lookup(&s, id_new, 2, 200))
         { printf("  PASS: oldest evicted, new ticket present\n"); g_pass++; }
    else { printf("  FAIL: eviction policy wrong\n"); g_fail++; }
}

static void test_tls_early_secret_schedule(void) {
    printf("== TLS early secret + binder key + c_e_traffic ==\n");

    /* Self-consistent vector: zero-PSK early_secret should equal
     * HKDF-Extract(00..00, 00..00). */
    uint8_t es[32];
    if (tls13_compute_early_secret(NULL, 0, es) == 0)
         { printf("  PASS: tls13_compute_early_secret(NULL) OK\n"); g_pass++; }
    else { printf("  FAIL: early_secret returns -1\n"); g_fail++; return; }

    uint8_t es_ref[32];
    {
        uint8_t zero32[32] = {0};
        hkdf_extract(zero32, 32, zero32, 32, es_ref);
    }
    if (memcmp(es, es_ref, 32) == 0)
         { printf("  PASS: zero-PSK early_secret matches HKDF-Extract(0,0)\n"); g_pass++; }
    else { printf("  FAIL: early_secret mismatch\n"); g_fail++; }

    /* PSK variant: with PSK={0xAA*32}, recompute and ensure it
     * differs from the zero-PSK one. */
    uint8_t psk[32]; memset(psk, 0xAA, 32);
    uint8_t es_psk[32];
    tls13_compute_early_secret(psk, 32, es_psk);
    if (memcmp(es_psk, es, 32) != 0)
         { printf("  PASS: PSK early_secret differs from zero variant\n"); g_pass++; }
    else { printf("  FAIL: PSK early_secret matches zero (HKDF broken)\n"); g_fail++; }

    /* binder_key: res vs ext distinct. */
    uint8_t bk_res[32], bk_ext[32];
    tls13_compute_binder_key(es_psk, 0, bk_res);
    tls13_compute_binder_key(es_psk, 1, bk_ext);
    if (memcmp(bk_res, bk_ext, 32) != 0)
         { printf("  PASS: res binder vs ext binder distinct\n"); g_pass++; }
    else { printf("  FAIL: binder labels collide\n"); g_fail++; }

    /* binder = Finished(binder_key, partial_ch_hash). Verify path. */
    uint8_t partial_hash[32]; memset(partial_hash, 0x55, 32);
    uint8_t binder_a[32], binder_b[32];
    tls13_compute_psk_binder(bk_res, partial_hash, binder_a);
    tls13_compute_finished(bk_res, partial_hash, binder_b);
    if (memcmp(binder_a, binder_b, 32) == 0)
         { printf("  PASS: binder == Finished(binder_key, hash)\n"); g_pass++; }
    else { printf("  FAIL: binder != Finished\n"); g_fail++; }

    /* c_e_traffic — sanity: nonzero and label-dependent. */
    uint8_t cet[32];
    tls13_compute_client_early_traffic_secret(es_psk, partial_hash, cet);
    uint8_t any = 0;
    for (int i = 0; i < 32; i++) any |= cet[i];
    if (any) { printf("  PASS: c_e_traffic_secret nonzero\n"); g_pass++; }
    else     { printf("  FAIL: c_e_traffic all zero\n"); g_fail++; }
}

static void test_tls_psk_extension_parser(void) {
    printf("== TLS pre_shared_key extension parser ==\n");

    /* Build a synthetic CH with one PSK identity + binder + the
     * extensions ordering rule (PSK MUST be last). */
    uint8_t ch[512];
    memset(ch, 0, sizeof(ch));
    /* Handshake header backfill at the end. */
    /* legacy_version */
    size_t i = 4;
    ch[i++] = 0x03; ch[i++] = 0x03;
    /* random[32] */
    memset(ch + i, 0xAB, 32); i += 32;
    /* legacy_session_id<0> */
    ch[i++] = 0;
    /* cipher_suites: [0x1303] */
    ch[i++] = 0x00; ch[i++] = 0x02;
    ch[i++] = 0x13; ch[i++] = 0x03;
    /* legacy_compression_methods: [0x00] */
    ch[i++] = 0x01; ch[i++] = 0x00;

    /* extensions block: backfill u16 length later. */
    size_t ext_len_off = i;
    i += 2;

    /* supported_versions = TLS 1.3. */
    ch[i++] = 0x00; ch[i++] = 0x2b;
    ch[i++] = 0x00; ch[i++] = 0x03;
    ch[i++] = 0x02;
    ch[i++] = 0x03; ch[i++] = 0x04;
    /* supported_groups = x25519. */
    ch[i++] = 0x00; ch[i++] = 0x0a;
    ch[i++] = 0x00; ch[i++] = 0x04;
    ch[i++] = 0x00; ch[i++] = 0x02;
    ch[i++] = 0x00; ch[i++] = 0x1d;
    /* key_share = single x25519 entry, all-zero pubkey (parser doesn't validate). */
    ch[i++] = 0x00; ch[i++] = 0x33;
    ch[i++] = 0x00; ch[i++] = 0x26;
    ch[i++] = 0x00; ch[i++] = 0x24;
    ch[i++] = 0x00; ch[i++] = 0x1d;
    ch[i++] = 0x00; ch[i++] = 0x20;
    /* x25519 pubkey: any nonzero so engine wouldn't choke. */
    for (int j = 0; j < 32; j++) ch[i++] = 0x42;
    /* signature_algorithms = ed25519. */
    ch[i++] = 0x00; ch[i++] = 0x0d;
    ch[i++] = 0x00; ch[i++] = 0x04;
    ch[i++] = 0x00; ch[i++] = 0x02;
    ch[i++] = 0x08; ch[i++] = 0x07;
    /* psk_key_exchange_modes = [psk_dhe_ke]. */
    ch[i++] = 0x00; ch[i++] = 0x2d;
    ch[i++] = 0x00; ch[i++] = 0x02;
    ch[i++] = 0x01;
    ch[i++] = 0x01;
    /* early_data (CH variant: empty body). */
    ch[i++] = 0x00; ch[i++] = 0x2a;
    ch[i++] = 0x00; ch[i++] = 0x00;

    /* pre_shared_key (MUST be last). One identity (8 bytes) + binder. */
    ch[i++] = 0x00; ch[i++] = 0x29;
    /* extension_data length: identities_total(2) + ids(2+8+4) + binders_total(2) + binder(1+32) = 51 */
    ch[i++] = 0x00; ch[i++] = 51;
    /* identities<7..>: 14 bytes ((u16 id_len + 8 + u32 age) = 14) */
    ch[i++] = 0x00; ch[i++] = 14;
    ch[i++] = 0x00; ch[i++] = 0x08;
    size_t expected_id_off = i;
    for (int j = 0; j < 8; j++) ch[i++] = (uint8_t)(0x10 + j);
    ch[i++] = 0xDE; ch[i++] = 0xAD; ch[i++] = 0xBE; ch[i++] = 0xEF;
    /* binders<33..>: u8 binder_len(32) + 32 bytes => total 33 */
    size_t expected_partial_off = i;
    ch[i++] = 0x00; ch[i++] = 33;
    ch[i++] = 32;
    size_t expected_binder_off = i;
    for (int j = 0; j < 32; j++) ch[i++] = (uint8_t)(0xB0 + j);

    /* Backfill extensions length. */
    size_t ext_total = i - (ext_len_off + 2);
    ch[ext_len_off]     = (uint8_t)(ext_total >> 8);
    ch[ext_len_off + 1] = (uint8_t)ext_total;

    /* Backfill handshake header. */
    ch[0] = 0x01;   /* client_hello */
    size_t hs_body = i - 4;
    ch[1] = (uint8_t)(hs_body >> 16);
    ch[2] = (uint8_t)(hs_body >> 8);
    ch[3] = (uint8_t)hs_body;

    tls13_client_hello_t out;
    if (tls13_parse_client_hello(ch, i, &out) == 0)
         { printf("  PASS: parse CH with PSK extension OK\n"); g_pass++; }
    else { printf("  FAIL: parse CH returned -1\n"); g_fail++; return; }

    if (out.psk_present == 1 && out.psk_offer_count == 1
        && out.psk_dhe_ke_offered == 1 && out.offers_early_data == 1)
         { printf("  PASS: PSK + psk_dhe_ke + early_data flags set\n"); g_pass++; }
    else { printf("  FAIL: psk_present=%d cnt=%u dhe=%d ed=%d\n",
                  out.psk_present, out.psk_offer_count,
                  out.psk_dhe_ke_offered, out.offers_early_data); g_fail++; }

    if (out.psk_id_off[0] == expected_id_off
        && out.psk_id_len[0] == 8
        && out.psk_obfuscated_age[0] == 0xdeadbeef
        && out.psk_binder_off[0] == expected_binder_off
        && out.psk_binder_len[0] == 32
        && out.psk_partial_ch_off == expected_partial_off)
         { printf("  PASS: id_off=%zu binder_off=%zu partial_off=%zu\n",
                  out.psk_id_off[0], out.psk_binder_off[0], out.psk_partial_ch_off); g_pass++; }
    else { printf("  FAIL: id_off=%zu(want %zu) binder_off=%zu(want %zu) partial_off=%zu(want %zu)\n",
                  out.psk_id_off[0], expected_id_off,
                  out.psk_binder_off[0], expected_binder_off,
                  out.psk_partial_ch_off, expected_partial_off); g_fail++; }

    /* Negative test: PSK NOT last must be rejected. Move PSK to before
     * sig_algorithms by swapping with early_data. Simpler: build a
     * CH where pre_shared_key is followed by an extra signature_algorithms.
     * Reuse `ch` buffer — append extra ext after PSK. */
    if (i + 8 < sizeof(ch)) {
        /* append 8-byte signature_algorithms after PSK. */
        ch[i++] = 0x00; ch[i++] = 0x0d;
        ch[i++] = 0x00; ch[i++] = 0x04;
        ch[i++] = 0x00; ch[i++] = 0x02;
        ch[i++] = 0x08; ch[i++] = 0x07;
        /* Patch ext_total + hs_len. */
        ext_total = i - (ext_len_off + 2);
        ch[ext_len_off]     = (uint8_t)(ext_total >> 8);
        ch[ext_len_off + 1] = (uint8_t)ext_total;
        hs_body = i - 4;
        ch[1] = (uint8_t)(hs_body >> 16);
        ch[2] = (uint8_t)(hs_body >> 8);
        ch[3] = (uint8_t)hs_body;
        if (tls13_parse_client_hello(ch, i, &out) == -1)
             { printf("  PASS: PSK-not-last -> parse rejects\n"); g_pass++; }
        else { printf("  FAIL: PSK-not-last accepted\n"); g_fail++; }
    }
}

/* ---------- TLS engine: PSK resumption acceptance ---------- */

static void test_engine_psk_resumption(void) {
    printf("== TLS engine: PSK resumption (server-side) ==\n");

    /* Pre-shared key + ticket id we'll plant in the store. The PSK is
     * 32 bytes per RFC 8446 §4.6.1 (size matches Hash output). */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) psk[i] = (uint8_t)(0x60 + i);
    const uint8_t ticket_id[8] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    pw_tls_ticket_store_t store;
    pw_tls_ticket_store_init(&store);
    if (pw_tls_ticket_store_insert(&store, ticket_id, sizeof(ticket_id),
                                   psk, 0xdeadbeef, 86400u,
                                   /*issued_at_ms*/ 1000u,
                                   /*max_early_data*/ 0u) == 0)
         { printf("  PASS: ticket inserted\n"); g_pass++; }
    else { printf("  FAIL: ticket insert\n"); g_fail++; return; }

    /* Build a CH that offers exactly this PSK. We drop signature_algorithms
     * (resumption doesn't need it) and append pre_shared_key as the LAST
     * extension. The binder must verify: HMAC(binder_key, partial_ch_hash). */
    uint8_t ch_rec[1024];
    memset(ch_rec, 0, sizeof(ch_rec));
    /* Reserve 5 bytes for record header. */
    uint8_t* p = ch_rec + 5;
    /* Handshake header: type=0x01 + 24-bit length backfilled */
    *p++ = 0x01;
    uint8_t* hs_len_at = p; p += 3;
    uint8_t* hs_body = p;

    *p++ = 0x03; *p++ = 0x03;                    /* legacy_version */
    for (int j = 0; j < 32; j++) *p++ = (uint8_t)(0xC0 + j); /* random[32] */
    *p++ = 0;                                     /* legacy_session_id len */
    *p++ = 0x00; *p++ = 0x02;                    /* cipher_suites length */
    *p++ = 0x13; *p++ = 0x03;                    /* TLS_CHACHA20_POLY1305_SHA256 */
    *p++ = 0x01; *p++ = 0x00;                    /* compression_methods */

    uint8_t* ext_len_at = p; p += 2;
    uint8_t* ext_start = p;

    /* supported_versions = TLS 1.3 */
    *p++ = 0x00; *p++ = 0x2b;
    *p++ = 0x00; *p++ = 0x03; *p++ = 0x02; *p++ = 0x03; *p++ = 0x04;
    /* supported_groups = x25519 */
    *p++ = 0x00; *p++ = 0x0a;
    *p++ = 0x00; *p++ = 0x04; *p++ = 0x00; *p++ = 0x02; *p++ = 0x00; *p++ = 0x1d;
    /* key_share = single x25519 entry, real client pubkey */
    uint8_t cli_priv[32];
    for (int j = 0; j < 32; j++) cli_priv[j] = (uint8_t)(0x55 ^ j);
    cli_priv[0] &= 248; cli_priv[31] &= 127; cli_priv[31] |= 64;
    uint8_t cli_pub[32];
    x25519(cli_pub, cli_priv, X25519_BASE_POINT);
    *p++ = 0x00; *p++ = 0x33;
    *p++ = 0x00; *p++ = 0x26;                    /* ext_data len = 38 */
    *p++ = 0x00; *p++ = 0x24;                    /* client_shares len = 36 */
    *p++ = 0x00; *p++ = 0x1d;                    /* x25519 */
    *p++ = 0x00; *p++ = 0x20;                    /* key length = 32 */
    memcpy(p, cli_pub, 32); p += 32;
    /* psk_key_exchange_modes = [psk_dhe_ke (0x01)] */
    *p++ = 0x00; *p++ = 0x2d;
    *p++ = 0x00; *p++ = 0x02;
    *p++ = 0x01; *p++ = 0x01;

    /* pre_shared_key (LAST). One identity. */
    *p++ = 0x00; *p++ = 0x29;
    /* ext_data len: identities_total(2) + (id_len(2)+8+age(4)) + binders_total(2) + binder(1+32)
     *             = 2 + 14 + 2 + 33 = 51 */
    *p++ = 0x00; *p++ = 51;
    *p++ = 0x00; *p++ = 14;                      /* identities_total */
    *p++ = 0x00; *p++ = 0x08;                    /* id_len = 8 */
    memcpy(p, ticket_id, 8); p += 8;
    /* obfuscated_ticket_age (any) */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* partial-CH ends here (RFC 8446 §4.2.11.2: hash includes everything
     * up to but NOT including the binders length-prefix). */
    uint8_t* binders_at = p;
    *p++ = 0x00; *p++ = 33;                      /* binders_total */
    *p++ = 32;                                    /* binder len */
    uint8_t* binder_at = p;
    memset(p, 0, 32); p += 32;                   /* placeholder, fill below */

    /* Backfill ext + hs lengths first (binder is computed over the PARTIAL
     * CH which excludes the binders<> field). */
    uint16_t ext_len = (uint16_t)(p - ext_start);
    ext_len_at[0] = (uint8_t)(ext_len >> 8);
    ext_len_at[1] = (uint8_t)ext_len;
    uint32_t hs_len = (uint32_t)(p - hs_body);
    hs_len_at[0] = (uint8_t)(hs_len >> 16);
    hs_len_at[1] = (uint8_t)(hs_len >> 8);
    hs_len_at[2] = (uint8_t)hs_len;

    /* Compute partial-CH hash + binder. partial_ch is the handshake msg
     * (NOT the record header) from byte 0 through binders_at-1. */
    size_t partial_off = (size_t)(binders_at - (ch_rec + 5));
    uint8_t partial_hash[32];
    sha256(ch_rec + 5, partial_off, partial_hash);
    uint8_t es[32], bk[32], binder[32];
    if (tls13_compute_early_secret(psk, 32, es) == 0
        && tls13_compute_binder_key(es, 0 /*resumption*/, bk) == 0
        && tls13_compute_psk_binder(bk, partial_hash, binder) == 0)
         { memcpy(binder_at, binder, 32);
           printf("  PASS: binder computed\n"); g_pass++; }
    else { printf("  FAIL: binder compute\n"); g_fail++; return; }

    /* Wrap in TLSPlaintext record header. */
    size_t body_len = (size_t)(p - (ch_rec + 5));
    ch_rec[0] = TLS_CT_HANDSHAKE;
    ch_rec[1] = 0x03; ch_rec[2] = 0x03;
    ch_rec[3] = (uint8_t)(body_len >> 8);
    ch_rec[4] = (uint8_t)body_len;
    size_t ch_total = 5 + body_len;

    /* Configure engine. The cert seed + cert chain are still required
     * by configure_server even though resumption skips Cert/CV. */
    uint8_t srv_seed[32];
    for (int j = 0; j < 32; j++) srv_seed[j] = (uint8_t)(0x40 + j);
    const uint8_t fake_cert[8] = { 0x30,0x06,0x05,0x00, 1,2,3,4 };
    const size_t  cert_lens[1] = { sizeof(fake_cert) };

    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    test_rng_state_t rng = { .next = 0 };
    if (pw_tls_engine_configure_server(eng, test_rng, &rng, srv_seed,
                                       fake_cert, cert_lens, 1) != 0)
         { printf("  FAIL: configure_server\n"); g_fail++; free(eng); return; }
    pw_tls_engine_attach_resumption(eng, &store);
    pw_tls_engine_set_clock(eng, 2000u);

    /* Feed CH and step. */
    size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
    memcpy(rx, ch_rec, ch_total);
    pw_tls_rx_ack(eng, ch_total);

    int want = pw_tls_step(eng);
    if (want >= 0
        && pw_tls_state(eng) == PW_TLS_ST_HANDSHAKE
        && pw_tls_hs_phase(eng) == PW_TLS_HS_AFTER_SF_AWAIT_CF
        && pw_tls_engine_was_resumed(eng))
         { printf("  PASS: engine accepted PSK and reached AFTER_SF_AWAIT_CF\n"); g_pass++; }
    else { printf("  FAIL: want=%d state=%d phase=%d resumed=%d\n",
                  want, pw_tls_state(eng), pw_tls_hs_phase(eng),
                  pw_tls_engine_was_resumed(eng));
           g_fail++; free(eng); return; }

    /* Inspect the TX buffer. First record is plaintext SH; verify it
     * carries a pre_shared_key extension (search for type 0x00 0x29). */
    size_t tx_len; const uint8_t* tx = pw_tls_tx_buf(eng, &tx_len);
    if (tx_len < 5 || tx[0] != TLS_CT_HANDSHAKE)
         { printf("  FAIL: first TX record not handshake\n"); g_fail++; free(eng); return; }
    uint16_t sh_body = ((uint16_t)tx[3] << 8) | tx[4];
    int found_psk_ext = 0;
    /* Scan SH body for the 0x00 0x29 marker. SH layout is small and
     * 0x0029 is a unique 2-byte token here so a linear scan is fine. */
    for (size_t off = 0; off + 1 < (size_t)sh_body; off++) {
        if (tx[5 + off] == 0x00 && tx[5 + off + 1] == 0x29) {
            found_psk_ext = 1; break;
        }
    }
    if (found_psk_ext) { printf("  PASS: SH carries pre_shared_key extension\n"); g_pass++; }
    else { printf("  FAIL: SH missing pre_shared_key extension\n"); g_fail++; }

    /* The remaining TX should be exactly TWO encrypted handshake records
     * (EE + sFin), not four (no Cert, no CV). Walk records past SH. */
    size_t off = 5 + (size_t)sh_body;
    int enc_records = 0;
    while (off + 5 <= tx_len) {
        uint16_t rec_body = ((uint16_t)tx[off + 3] << 8) | tx[off + 4];
        if (off + 5 + rec_body > tx_len) break;
        enc_records++;
        off += 5 + rec_body;
    }
    if (enc_records == 2)
         { printf("  PASS: server flight has exactly 2 encrypted records (EE + sFin)\n"); g_pass++; }
    else { printf("  FAIL: server flight had %d encrypted records (expected 2)\n",
                  enc_records); g_fail++; }

    free(eng);
}



/* ---------- TLS engine: 0-RTT acceptance ---------- */

static void test_engine_0rtt_acceptance(void) {
    printf("== TLS engine: 0-RTT (early data) acceptance ==\n");

    uint8_t psk[32];
    for (int i = 0; i < 32; i++) psk[i] = (uint8_t)(0x70 + i);
    const uint8_t ticket_id[8] = { 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27 };

    pw_tls_ticket_store_t store;
    pw_tls_ticket_store_init(&store);
    if (pw_tls_ticket_store_insert(&store, ticket_id, sizeof(ticket_id),
                                   psk, 0xcafebabe, 86400u, 1000u,
                                   /*max_early_data*/ 16384u) != 0)
         { printf("  FAIL: ticket insert\n"); g_fail++; return; }

    uint8_t ch_rec[1024];
    memset(ch_rec, 0, sizeof(ch_rec));
    uint8_t* p = ch_rec + 5;
    *p++ = 0x01;
    uint8_t* hs_len_at = p; p += 3;
    uint8_t* hs_body = p;

    *p++ = 0x03; *p++ = 0x03;
    for (int j = 0; j < 32; j++) *p++ = (uint8_t)(0xD0 + j);
    *p++ = 0;
    *p++ = 0x00; *p++ = 0x02; *p++ = 0x13; *p++ = 0x03;
    *p++ = 0x01; *p++ = 0x00;

    uint8_t* ext_len_at = p; p += 2;
    uint8_t* ext_start = p;

    *p++ = 0x00; *p++ = 0x2b;
    *p++ = 0x00; *p++ = 0x03; *p++ = 0x02; *p++ = 0x03; *p++ = 0x04;
    *p++ = 0x00; *p++ = 0x0a;
    *p++ = 0x00; *p++ = 0x04; *p++ = 0x00; *p++ = 0x02; *p++ = 0x00; *p++ = 0x1d;
    uint8_t cli_priv[32];
    for (int j = 0; j < 32; j++) cli_priv[j] = (uint8_t)(0x44 ^ j);
    cli_priv[0] &= 248; cli_priv[31] &= 127; cli_priv[31] |= 64;
    uint8_t cli_pub[32];
    x25519(cli_pub, cli_priv, X25519_BASE_POINT);
    *p++ = 0x00; *p++ = 0x33;
    *p++ = 0x00; *p++ = 0x26;
    *p++ = 0x00; *p++ = 0x24;
    *p++ = 0x00; *p++ = 0x1d;
    *p++ = 0x00; *p++ = 0x20;
    memcpy(p, cli_pub, 32); p += 32;
    *p++ = 0x00; *p++ = 0x2d;
    *p++ = 0x00; *p++ = 0x02; *p++ = 0x01; *p++ = 0x01;
    *p++ = 0x00; *p++ = 0x2a;
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x29;
    *p++ = 0x00; *p++ = 51;
    *p++ = 0x00; *p++ = 14;
    *p++ = 0x00; *p++ = 0x08;
    memcpy(p, ticket_id, 8); p += 8;
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    uint8_t* binders_at = p;
    *p++ = 0x00; *p++ = 33;
    *p++ = 32;
    uint8_t* binder_at = p;
    memset(p, 0, 32); p += 32;

    uint16_t ext_len = (uint16_t)(p - ext_start);
    ext_len_at[0] = (uint8_t)(ext_len >> 8);
    ext_len_at[1] = (uint8_t)ext_len;
    uint32_t hs_len = (uint32_t)(p - hs_body);
    hs_len_at[0] = (uint8_t)(hs_len >> 16);
    hs_len_at[1] = (uint8_t)(hs_len >> 8);
    hs_len_at[2] = (uint8_t)hs_len;

    size_t partial_off = (size_t)(binders_at - (ch_rec + 5));
    uint8_t partial_hash[32];
    sha256(ch_rec + 5, partial_off, partial_hash);
    uint8_t es[32], bk[32], binder[32];
    if (tls13_compute_early_secret(psk, 32, es) != 0
        || tls13_compute_binder_key(es, 0, bk) != 0
        || tls13_compute_psk_binder(bk, partial_hash, binder) != 0)
         { printf("  FAIL: binder compute\n"); g_fail++; return; }
    memcpy(binder_at, binder, 32);

    size_t body_len = (size_t)(p - (ch_rec + 5));
    ch_rec[0] = TLS_CT_HANDSHAKE;
    ch_rec[1] = 0x03; ch_rec[2] = 0x03;
    ch_rec[3] = (uint8_t)(body_len >> 8);
    ch_rec[4] = (uint8_t)body_len;
    size_t ch_total = 5 + body_len;

    uint8_t srv_seed[32];
    for (int j = 0; j < 32; j++) srv_seed[j] = (uint8_t)(0x50 + j);
    const uint8_t fake_cert[8] = { 0x30,0x06,0x05,0x00, 1,2,3,4 };
    const size_t  cert_lens[1] = { sizeof(fake_cert) };

    pw_tls_engine_t* eng = malloc(sizeof(*eng));
    pw_tls_engine_init(eng);
    test_rng_state_t rng = { .next = 0 };
    if (pw_tls_engine_configure_server(eng, test_rng, &rng, srv_seed,
                                       fake_cert, cert_lens, 1) != 0)
         { printf("  FAIL: configure_server\n"); g_fail++; free(eng); return; }
    pw_tls_engine_attach_resumption(eng, &store);
    pw_tls_engine_set_clock(eng, 2000u);

    size_t cap; uint8_t* rx = pw_tls_rx_buf(eng, &cap);
    memcpy(rx, ch_rec, ch_total);
    pw_tls_rx_ack(eng, ch_total);
    int want = pw_tls_step(eng);
    if (want >= 0
        && pw_tls_engine_was_resumed(eng)
        && pw_tls_engine_early_data_accepted(eng))
         { printf("  PASS: engine accepted PSK + 0-RTT\n"); g_pass++; }
    else { printf("  FAIL: resumed=%d ed=%d\n",
                  pw_tls_engine_was_resumed(eng),
                  pw_tls_engine_early_data_accepted(eng));
           g_fail++; free(eng); return; }

    /* Independently derive c_e_traffic and seal an early-data record. */
    uint8_t ce_secret[32], ce_key[32], ce_iv[12];
    {
        uint8_t th_ch[32];
        sha256(ch_rec + 5, ch_total - 5, th_ch);
        uint8_t es2[32];
        if (tls13_compute_early_secret(psk, 32, es2) != 0
            || tls13_compute_client_early_traffic_secret(es2, th_ch, ce_secret) != 0)
             { printf("  FAIL: derive c_e_traffic\n"); g_fail++; free(eng); return; }
        tls13_derive_traffic_keys(ce_secret, ce_key, ce_iv);
    }
    tls_record_dir_t cli_ed; memset(&cli_ed, 0, sizeof(cli_ed));
    memcpy(cli_ed.key,       ce_key, 32);
    memcpy(cli_ed.static_iv, ce_iv,  12);

    const uint8_t early_pt[] = "EARLY!";
    uint8_t ed_rec[256];
    size_t ed_wire = tls13_seal_record(&cli_ed,
                                       TLS_CT_APPLICATION_DATA,
                                       TLS_CT_APPLICATION_DATA,
                                       early_pt, sizeof(early_pt) - 1,
                                       ed_rec, sizeof(ed_rec));
    if (ed_wire == 0) { printf("  FAIL: seal early data\n"); g_fail++; free(eng); return; }

    rx = pw_tls_rx_buf(eng, &cap);
    memcpy(rx, ed_rec, ed_wire);
    pw_tls_rx_ack(eng, ed_wire);
    pw_tls_step(eng);
    size_t app_in_len; const uint8_t* app_in = pw_tls_app_in_buf(eng, &app_in_len);
    if (app_in_len == sizeof(early_pt) - 1
        && memcmp(app_in, early_pt, app_in_len) == 0)
         { printf("  PASS: early-data plaintext surfaced via APP_IN\n"); g_pass++; }
    else { printf("  FAIL: app_in_len=%zu\n", app_in_len); g_fail++; }

    pw_tls_app_in_ack(eng, app_in_len);

    /* EOED under c_e_traffic. */
    uint8_t eoed_msg[4] = { 0x05, 0x00, 0x00, 0x00 };
    uint8_t eoed_rec[64];
    size_t eoed_wire = tls13_seal_record(&cli_ed,
                                         TLS_CT_HANDSHAKE,
                                         TLS_CT_APPLICATION_DATA,
                                         eoed_msg, 4,
                                         eoed_rec, sizeof(eoed_rec));
    if (eoed_wire == 0) { printf("  FAIL: seal EOED\n"); g_fail++; free(eng); return; }
    rx = pw_tls_rx_buf(eng, &cap);
    memcpy(rx, eoed_rec, eoed_wire);
    pw_tls_rx_ack(eng, eoed_wire);
    pw_tls_step(eng);

    if (pw_tls_state(eng) == PW_TLS_ST_HANDSHAKE
        && pw_tls_hs_phase(eng) == PW_TLS_HS_AFTER_SF_AWAIT_CF)
         { printf("  PASS: EOED consumed; engine still in AFTER_SF_AWAIT_CF\n"); g_pass++; }
    else { printf("  FAIL: post-EOED state=%d phase=%d\n",
                  pw_tls_state(eng), pw_tls_hs_phase(eng));
           g_fail++; }

    free(eng);
}



#include "../io/dpdk.h"

static void test_dpdk_stub(void) {
    printf("== DPDK backend stub (WITH_DPDK undefined) ==\n");

    /* In stub mode (no -DWITH_DPDK=1), pw_dpdk_init MUST return -1
     * with a clear error message, and pump/shutdown MUST be safe
     * no-ops. This locks in the invariant that a binary built
     * without DPDK can still link the userspace tree and reject
     * --dpdk at runtime instead of crashing. */
    pw_dpdk_cfg_t cfg = { .port_id = 0, .on_segment = NULL, .user = NULL };
    pw_dpdk_ctx_t ctx;
    /* Suppress the helpful-error stderr to keep test output clean. */
    fflush(stderr);
    int saved_err = dup(2);
    int devnull   = open("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2(devnull, 2); close(devnull); }

    int rc = pw_dpdk_init(0, NULL, &cfg, &ctx);

    fflush(stderr);
    if (saved_err >= 0) { dup2(saved_err, 2); close(saved_err); }

    if (rc == -1) { printf("  PASS: stub init returns -1\n"); g_pass++; }
    else          { printf("  FAIL: stub init rc=%d\n", rc); g_fail++; }

    int prc = pw_dpdk_pump(&ctx);
    if (prc == -1) { printf("  PASS: stub pump returns -1\n"); g_pass++; }
    else           { printf("  FAIL: stub pump rc=%d\n", prc); g_fail++; }

    /* Must not segfault. */
    pw_dpdk_shutdown(&ctx);
    printf("  PASS: stub shutdown is a no-op\n"); g_pass++;
}

int main(void) {
    /* Pick the best SHA-256 + ChaCha20 impls available; tests below
     * run through the public entry points so they exercise whichever
     * path is selected. */
    sha256_select_impl();
    chacha20_select_impl();
    printf("[info] cpu_features sse2=%u ssse3=%u sse41=%u sha=%u neon=%u arm_sha2=%u\n",
           cpu_features()->x86_sse2,  cpu_features()->x86_ssse3,
           cpu_features()->x86_sse41, cpu_features()->x86_sha,
           cpu_features()->arm_neon,  cpu_features()->arm_sha2);
    printf("[info] sha256 impl   = %s\n", sha256_impl_name());
    printf("[info] chacha20 impl = %s\n", chacha20_impl_name());

    test_sha256();
    test_sha256_dispatch();
    test_sha512();
    test_hmac_sha256();
    test_hkdf();
    test_chacha20();
    test_chacha20_dispatch();
    test_poly1305();
    test_aead_chacha20_poly1305();
    test_x25519();
    test_ed25519();
    test_tls13_keysched();
    test_tls13_record();
    test_ip_tcp();
    test_tcp_state();
    test_tcp_zero_window();
    test_tcp_retransmit_rto();
    test_tcp_congestion_control();
    test_buffer_pool();
    test_pem();
    test_cert_store();
    test_tls13_handshake();
    test_chacha20_stream_iov();
    test_aead_seal_iov();
    test_tls13_record_iov();
    test_pw_conn();
    test_tls13_finished();
    test_tls13_build_messages();
    test_tls13_certificate_verify();
    test_tls13_transcript();
    test_dispatch_table();
    test_tcp_dispatch();
    test_tls_engine();
    test_engine_via_dispatch();
    test_engine_handshake_server();
    test_engine_handshake_roundtrip();
    test_engine_tolerates_dummy_ccs();
    test_engine_tolerates_dummy_ccs_split();
    test_engine_fatal_wipes_tx_and_keys();
    test_engine_last_error_protocol();
    test_engine_last_error_init();
    test_pw_rx_reassembly_slot_sizing();
    test_engine_pool();
    test_tls_ticket_store();
    test_tls_early_secret_schedule();
    test_tls_psk_extension_parser();
    test_engine_psk_resumption();
    test_engine_0rtt_acceptance();
    test_dpdk_stub();

    printf("\n=== RESULTS: PASS=%d FAIL=%d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
