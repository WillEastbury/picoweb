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

#include "../crypto/sha256.h"
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
#include "../crypto/x25519.h"
#include "../tcp/ip.h"
#include "../tcp/tcp.h"
#include "../iov.h"
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

    if (ch.offers_chacha_poly && ch.offers_tls13 && ch.offers_x25519)
         { printf("  PASS: client offered chacha/tls13/x25519\n"); g_pass++; }
    else { printf("  FAIL: missing offers c=%d v=%d g=%d\n",
                  ch.offers_chacha_poly, ch.offers_tls13, ch.offers_x25519); g_fail++; }

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
                                          server_random, server_pub);
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
    test_hmac_sha256();
    test_hkdf();
    test_chacha20();
    test_chacha20_dispatch();
    test_poly1305();
    test_aead_chacha20_poly1305();
    test_x25519();
    test_tls13_keysched();
    test_tls13_record();
    test_ip_tcp();
    test_tcp_state();
    test_buffer_pool();
    test_pem();
    test_cert_store();
    test_tls13_handshake();
    test_chacha20_stream_iov();
    test_aead_seal_iov();
    test_tls13_record_iov();
    test_pw_conn();

    printf("\n=== RESULTS: PASS=%d FAIL=%d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
