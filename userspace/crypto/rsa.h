#ifndef PICOWEB_USERSPACE_CRYPTO_RSA_H
#define PICOWEB_USERSPACE_CRYPTO_RSA_H

#include <stddef.h>
#include <stdint.h>

#define PW_RSA_MAX_BITS  4096u
#define PW_RSA_MAX_LIMBS (PW_RSA_MAX_BITS / 64u)

typedef struct {
    size_t n_len;                      /* modulus byte length (k) */
    size_t n_limbs;                    /* ceil(k / 8)             */
    uint64_t n[PW_RSA_MAX_LIMBS];      /* little-endian limbs     */
    uint64_t d[PW_RSA_MAX_LIMBS];      /* little-endian limbs     */
    uint64_t r2[PW_RSA_MAX_LIMBS];     /* R^2 mod n               */
    uint64_t n0_inv;                   /* -n^{-1} mod 2^64        */
} pw_rsa_private_key_t;

/* Parse a DER private key (PKCS#1 RSAPrivateKey, or PKCS#8 wrapping it)
 * into a runtime key for private exponentiation.
 * Returns 0 on success, -1 on parse/size/format errors. */
int pw_rsa_private_key_from_der(const uint8_t* der, size_t der_len,
                                pw_rsa_private_key_t* out);

/* RSASP1 primitive: sig = em^d mod n.
 * `em` must be exactly modulus length (key->n_len) bytes, big-endian.
 * `sig_out_cap` must be >= key->n_len.
 * Returns 0 on success, -1 on error. */
int pw_rsa_rsasp1(const pw_rsa_private_key_t* key,
                  const uint8_t* em, size_t em_len,
                  uint8_t* sig_out, size_t sig_out_cap);

#endif
