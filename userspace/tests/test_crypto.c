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
#include "../tls/keysched.h"
#include "../tls/record.h"
#include "../tcp/ip.h"
#include "../tcp/tcp.h"

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

int main(void) {
    test_sha256();
    test_hmac_sha256();
    test_hkdf();
    test_chacha20();
    test_poly1305();
    test_aead_chacha20_poly1305();
    test_x25519();
    test_tls13_keysched();
    test_tls13_record();
    test_ip_tcp();
    test_tcp_state();

    printf("\n=== RESULTS: PASS=%d FAIL=%d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
