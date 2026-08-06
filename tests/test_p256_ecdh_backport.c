/*
 * Backport verification test for p256_scalar_mul_point() (general-point
 * ECDH multiply), added to close the gap documented in picocrypto's own
 * README ("General P-256 point arithmetic for an arbitrary point ... isn't
 * in p256.c yet"). Same independent vectors used to validate the PIOS
 * backport source (generated with Python's `cryptography` library,
 * ec.SECP256R1 + ec.ECDH()).
 */
#include "p256.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void hex_to_bytes(const char *hex, uint8_t *out, uint32_t out_len) {
    for (uint32_t i = 0; i < out_len; i++)
        out[i] = (uint8_t)((hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]));
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, uint32_t n) {
    return memcmp(a, b, n) == 0;
}

int main(void) {
    int failures = 0;

    const char *priv_a_hex = "001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
    const char *pub_a_hex  = "042d562a617e9dfb0437d6613a0386fbb9c2418e8e8957d4d7a9fd7b151888327"
                             "a38ecd7d9b6b166746d85b974fb8a6b9fd2bab38b9a40eddb6008a380d0786ccf";
    const char *priv_b_hex = "00fedcba0987654321fedcba0987654321fedcba0987654321fedcba09876543";
    const char *pub_b_hex  = "04aafecb2037f24bc052950b13f839100a80450d39f57361041b576d52b6be42"
                             "944e7d9955e58677795f71409d6eb13e09d9c9dbb40f9c705b85227b38ef8fe738";
    const char *shared_hex = "80ff8c50d12c9abfd0a3bfee1e8c14e758078259821cd824c8f909987454a577";

    uint8_t priv_a[32], pub_a[65], priv_b[32], pub_b[65];
    uint8_t shared_x_expected[32];
    hex_to_bytes(priv_a_hex, priv_a, 32);
    hex_to_bytes(pub_a_hex, pub_a, 65);
    hex_to_bytes(priv_b_hex, priv_b, 32);
    hex_to_bytes(pub_b_hex, pub_b, 65);
    hex_to_bytes(shared_hex, shared_x_expected, 32);

    uint8_t derived_pub_a[65], derived_pub_b[65];
    if (p256_derive_pubkey(priv_a, derived_pub_a) != 0 || !bytes_eq(derived_pub_a, pub_a, 65)) {
        printf("[FAIL] p256_derive_pubkey(priv_a) mismatch\n"); failures++;
    } else printf("[PASS] p256_derive_pubkey(priv_a) matches independent vector\n");

    if (p256_derive_pubkey(priv_b, derived_pub_b) != 0 || !bytes_eq(derived_pub_b, pub_b, 65)) {
        printf("[FAIL] p256_derive_pubkey(priv_b) mismatch\n"); failures++;
    } else printf("[PASS] p256_derive_pubkey(priv_b) matches independent vector\n");

    uint8_t shared_ab[64], shared_ba[64];
    if (p256_scalar_mul_point(priv_a, pub_b, shared_ab) != 0) {
        printf("[FAIL] p256_scalar_mul_point(priv_a, pub_b) returned error\n"); failures++;
    } else if (p256_scalar_mul_point(priv_b, pub_a, shared_ba) != 0) {
        printf("[FAIL] p256_scalar_mul_point(priv_b, pub_a) returned error\n"); failures++;
    } else if (!bytes_eq(shared_ab, shared_ba, 64)) {
        printf("[FAIL] ECDH(priv_a,pub_b) != ECDH(priv_b,pub_a)\n"); failures++;
    } else if (!bytes_eq(shared_ab, shared_x_expected, 32)) {
        printf("[FAIL] ECDH shared x-coordinate does not match independent vector\n"); failures++;
    } else {
        printf("[PASS] ECDH(priv_a,pub_b) == ECDH(priv_b,pub_a) == independent vector\n");
    }

    uint8_t bad_pub[65];
    memcpy(bad_pub, pub_a, 65);
    bad_pub[0] = 0x02;
    uint8_t scratch[64];
    if (p256_scalar_mul_point(priv_a, bad_pub, scratch) == 0) {
        printf("[FAIL] accepted a bad point-format prefix\n"); failures++;
    } else printf("[PASS] rejects bad point-format prefix\n");

    memcpy(bad_pub, pub_a, 65);
    bad_pub[0] = 0x04;
    bad_pub[10] ^= 0xFF;
    if (p256_scalar_mul_point(priv_a, bad_pub, scratch) == 0) {
        printf("[FAIL] accepted an off-curve point\n"); failures++;
    } else printf("[PASS] rejects an off-curve point\n");

    uint8_t zero_scalar[32];
    memset(zero_scalar, 0, sizeof(zero_scalar));
    if (p256_scalar_mul_point(zero_scalar, pub_a, scratch) == 0) {
        printf("[FAIL] accepted an all-zero scalar\n"); failures++;
    } else printf("[PASS] rejects an all-zero scalar\n");

    if (failures == 0) { printf("test_p256_ecdh_backport: ALL PASS\n"); return 0; }
    printf("test_p256_ecdh_backport: %d FAILURE(S)\n", failures);
    return 1;
}
