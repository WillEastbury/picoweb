#include "rsa.h"

#include <string.h>

#include "util.h"

static int der_read_tlv(const uint8_t* der, size_t der_len, size_t* off,
                        uint8_t* tag, const uint8_t** val, size_t* val_len) {
    if (!der || !off || !tag || !val || !val_len) return -1;
    if (*off + 2 > der_len) return -1;
    uint8_t t = der[*off];
    uint8_t l1 = der[*off + 1];
    size_t len = 0, hdr = 2;
    if (l1 < 0x80) {
        len = l1;
    } else {
        uint8_t n = l1 & 0x7f;
        if (n == 0 || n > 4 || *off + 2 + n > der_len) return -1;
        hdr += n;
        for (uint8_t i = 0; i < n; i++) len = (len << 8) | der[*off + 2 + i];
    }
    if (*off + hdr + len > der_len) return -1;
    *tag = t;
    *val = der + *off + hdr;
    *val_len = len;
    *off += hdr + len;
    return 0;
}

static int rsa_pkcs1_from_der(const uint8_t* der, size_t der_len,
                              const uint8_t** pkcs1, size_t* pkcs1_len) {
    if (!der || !pkcs1 || !pkcs1_len) return -1;
    *pkcs1 = der;
    *pkcs1_len = der_len;

    /* If DER is PKCS#8 PrivateKeyInfo, pull inner OCTET STRING. */
    size_t o = 0;
    uint8_t t; const uint8_t* v; size_t vl;
    if (der_read_tlv(der, der_len, &o, &t, &v, &vl) != 0 || t != 0x30) return -1;
    size_t s = 0;
    uint8_t t1; const uint8_t* v1; size_t l1;
    if (der_read_tlv(v, vl, &s, &t1, &v1, &l1) != 0 || t1 != 0x02) return -1; /* version */
    uint8_t t2; const uint8_t* v2; size_t l2;
    if (der_read_tlv(v, vl, &s, &t2, &v2, &l2) != 0) return -1;
    if (t2 == 0x30) {
        uint8_t t3; const uint8_t* v3; size_t l3;
        if (der_read_tlv(v, vl, &s, &t3, &v3, &l3) == 0 && t3 == 0x04) {
            *pkcs1 = v3;
            *pkcs1_len = l3;
        }
    }
    return 0;
}

static int int_copy_strip_leading_zero(const uint8_t* in, size_t in_len,
                                       uint8_t* out, size_t out_cap,
                                       size_t* out_len) {
    while (in_len > 0 && *in == 0x00) {
        in++;
        in_len--;
    }
    if (in_len == 0 || in_len > out_cap) return -1;
    memcpy(out, in, in_len);
    *out_len = in_len;
    return 0;
}

static void be_to_limbs(const uint8_t* be, size_t be_len,
                        uint64_t* out, size_t limbs_cap) {
    memset(out, 0, limbs_cap * sizeof(uint64_t));
    size_t li = 0;
    size_t i = be_len;
    while (i > 0 && li < limbs_cap) {
        uint64_t w = 0;
        for (unsigned b = 0; b < 8 && i > 0; b++) {
            i--;
            w |= (uint64_t)be[i] << (8u * b);
        }
        out[li++] = w;
    }
}

static void limbs_to_be(const uint64_t* limbs, size_t n_len, uint8_t* out) {
    memset(out, 0, n_len);
    for (size_t i = 0; i < n_len; i++) {
        size_t bit_off = i * 8u;
        size_t li = bit_off / 64u;
        size_t bo = bit_off % 64u;
        uint64_t v = limbs[li] >> bo;
        if (bo > 56 && li + 1 < PW_RSA_MAX_LIMBS) v |= limbs[li + 1] << (64u - bo);
        out[n_len - 1 - i] = (uint8_t)v;
    }
}

static int limbs_cmp(const uint64_t* a, const uint64_t* b, size_t n) {
    for (size_t i = n; i > 0; i--) {
        uint64_t av = a[i - 1], bv = b[i - 1];
        if (av < bv) return -1;
        if (av > bv) return 1;
    }
    return 0;
}

static uint64_t limbs_sub_inplace(uint64_t* a, const uint64_t* b, size_t n) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < n; i++) {
        __uint128_t sub = (__uint128_t)b[i] + (__uint128_t)borrow;
        uint64_t bi = (uint64_t)sub;
        uint64_t carry_from_add = (uint64_t)(sub >> 64);
        uint64_t ai = a[i];
        a[i] = ai - bi;
        uint64_t borrow_from_sub = (ai < bi) ? 1u : 0u;
        borrow = (carry_from_add | borrow_from_sub);
    }
    return borrow;
}

static void mod_double(uint64_t* x, const uint64_t* n, size_t k) {
    uint64_t carry = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t v = x[i];
        x[i] = (v << 1) | carry;
        carry = v >> 63;
    }
    if (carry || limbs_cmp(x, n, k) >= 0) (void)limbs_sub_inplace(x, n, k);
}

static uint64_t mont_n0_inv(uint64_t n0) {
    uint64_t x = 1;
    for (int i = 0; i < 6; i++) x *= (uint64_t)(2 - n0 * x);
    return (uint64_t)(0 - x);
}

static void mont_mul(uint64_t* out,
                     const uint64_t* a,
                     const uint64_t* b,
                     const uint64_t* n,
                     uint64_t n0_inv,
                     size_t k) {
    uint64_t t[2 * PW_RSA_MAX_LIMBS + 2];
    memset(t, 0, sizeof(t));

    for (size_t i = 0; i < k; i++) {
        __uint128_t carry = 0;
        for (size_t j = 0; j < k; j++) {
            __uint128_t z = (__uint128_t)a[i] * b[j] + t[i + j] + carry;
            t[i + j] = (uint64_t)z;
            carry = z >> 64;
        }
        size_t idx = i + k;
        __uint128_t z = (__uint128_t)t[idx] + carry;
        t[idx] = (uint64_t)z;
        carry = z >> 64;
        while (carry) {
            idx++;
            z = (__uint128_t)t[idx] + carry;
            t[idx] = (uint64_t)z;
            carry = z >> 64;
        }
    }

    for (size_t i = 0; i < k; i++) {
        uint64_t m = t[i] * n0_inv;
        __uint128_t carry = 0;
        for (size_t j = 0; j < k; j++) {
            __uint128_t z = (__uint128_t)m * n[j] + t[i + j] + carry;
            t[i + j] = (uint64_t)z;
            carry = z >> 64;
        }
        size_t idx = i + k;
        __uint128_t z = (__uint128_t)t[idx] + carry;
        t[idx] = (uint64_t)z;
        carry = z >> 64;
        while (carry) {
            idx++;
            z = (__uint128_t)t[idx] + carry;
            t[idx] = (uint64_t)z;
            carry = z >> 64;
        }
    }

    uint64_t top = t[2 * k];
    memcpy(out, t + k, k * sizeof(uint64_t));
    /* CIOS Montgomery reduction yields a (k+1)-limb candidate. When the
     * extra top limb is non-zero, one subtraction is still required even if
     * the low k limbs compare < n. */
    if (top || limbs_cmp(out, n, k) >= 0) (void)limbs_sub_inplace(out, n, k);
    secure_zero(t, sizeof(t));
}

static int limbs_bitlen(const uint64_t* x, size_t k) {
    for (size_t i = k; i > 0; i--) {
        uint64_t w = x[i - 1];
        if (!w) continue;
        int bits = 0;
        while (w) { bits++; w >>= 1; }
        return (int)((i - 1) * 64 + (size_t)bits);
    }
    return 0;
}

static int limbs_get_bit(const uint64_t* x, size_t bit) {
    size_t i = bit / 64u;
    size_t o = bit % 64u;
    return (int)((x[i] >> o) & 1u);
}

int pw_rsa_private_key_from_der(const uint8_t* der, size_t der_len,
                                pw_rsa_private_key_t* out) {
    if (!der || !out) return -1;
    memset(out, 0, sizeof(*out));

    const uint8_t* pkcs1 = NULL;
    size_t pkcs1_len = 0;
    if (rsa_pkcs1_from_der(der, der_len, &pkcs1, &pkcs1_len) != 0) return -1;

    size_t o = 0;
    uint8_t t; const uint8_t* v; size_t vl;
    if (der_read_tlv(pkcs1, pkcs1_len, &o, &t, &v, &vl) != 0 || t != 0x30) return -1;

    size_t s = 0;
    uint8_t ti; const uint8_t* vi; size_t li;
    if (der_read_tlv(v, vl, &s, &ti, &vi, &li) != 0 || ti != 0x02) return -1; /* version */
    if (der_read_tlv(v, vl, &s, &ti, &vi, &li) != 0 || ti != 0x02) return -1; /* n */
    uint8_t n_be[PW_RSA_MAX_BITS / 8];
    size_t n_len = 0;
    if (int_copy_strip_leading_zero(vi, li, n_be, sizeof(n_be), &n_len) != 0) return -1;

    if (der_read_tlv(v, vl, &s, &ti, &vi, &li) != 0 || ti != 0x02) return -1; /* e */
    if (der_read_tlv(v, vl, &s, &ti, &vi, &li) != 0 || ti != 0x02) return -1; /* d */
    uint8_t d_be[PW_RSA_MAX_BITS / 8];
    size_t d_len = 0;
    if (int_copy_strip_leading_zero(vi, li, d_be, sizeof(d_be), &d_len) != 0) return -1;

    if (n_len < 64 || n_len > sizeof(n_be)) return -1;
    if (n_be[0] == 0) return -1;
    if ((n_be[n_len - 1] & 1u) == 0) return -1; /* odd modulus required */

    out->n_len = n_len;
    out->n_limbs = (n_len + 7u) / 8u;
    if (out->n_limbs == 0 || out->n_limbs > PW_RSA_MAX_LIMBS) return -1;

    be_to_limbs(n_be, n_len, out->n, out->n_limbs);
    be_to_limbs(d_be, d_len, out->d, out->n_limbs);
    if (limbs_cmp(out->d, out->n, out->n_limbs) >= 0) return -1;

    out->n0_inv = mont_n0_inv(out->n[0]);

    uint64_t rr[PW_RSA_MAX_LIMBS];
    memset(rr, 0, sizeof(rr));
    rr[0] = 1;
    for (size_t i = 0; i < 2u * out->n_limbs * 64u; i++) mod_double(rr, out->n, out->n_limbs);
    memcpy(out->r2, rr, out->n_limbs * sizeof(uint64_t));
    secure_zero(rr, sizeof(rr));
    secure_zero(n_be, sizeof(n_be));
    secure_zero(d_be, sizeof(d_be));
    return 0;
}

int pw_rsa_rsasp1(const pw_rsa_private_key_t* key,
                  const uint8_t* em, size_t em_len,
                  uint8_t* sig_out, size_t sig_out_cap) {
    if (!key || !em || !sig_out) return -1;
    size_t k = key->n_limbs;
    if (k == 0 || em_len != key->n_len || sig_out_cap < key->n_len) return -1;

    uint64_t m[PW_RSA_MAX_LIMBS], one[PW_RSA_MAX_LIMBS];
    uint64_t base_m[PW_RSA_MAX_LIMBS], acc[PW_RSA_MAX_LIMBS], tmp[PW_RSA_MAX_LIMBS];
    memset(m, 0, sizeof(m));
    memset(one, 0, sizeof(one));
    memset(base_m, 0, sizeof(base_m));
    memset(acc, 0, sizeof(acc));
    memset(tmp, 0, sizeof(tmp));

    be_to_limbs(em, em_len, m, k);
    if (limbs_cmp(m, key->n, k) >= 0) return -1;
    one[0] = 1;

    mont_mul(base_m, m, key->r2, key->n, key->n0_inv, k);
    mont_mul(acc, one, key->r2, key->n, key->n0_inv, k);

    int d_bits = limbs_bitlen(key->d, k);
    if (d_bits <= 0) return -1;
    for (int bit = d_bits - 1; bit >= 0; bit--) {
        mont_mul(tmp, acc, acc, key->n, key->n0_inv, k);
        memcpy(acc, tmp, k * sizeof(uint64_t));
        if (limbs_get_bit(key->d, (size_t)bit)) {
            mont_mul(tmp, acc, base_m, key->n, key->n0_inv, k);
            memcpy(acc, tmp, k * sizeof(uint64_t));
        }
    }

    mont_mul(tmp, acc, one, key->n, key->n0_inv, k); /* out of Montgomery domain */
    limbs_to_be(tmp, key->n_len, sig_out);
    secure_zero(m, sizeof(m));
    secure_zero(one, sizeof(one));
    secure_zero(base_m, sizeof(base_m));
    secure_zero(acc, sizeof(acc));
    secure_zero(tmp, sizeof(tmp));
    return 0;
}

int pw_rsa_self_check(const pw_rsa_private_key_t* key,
                      const uint8_t* em, size_t em_len,
                      const uint8_t* sig, size_t sig_len) {
    /* Verify sig^65537 mod n == em using Montgomery. */
    if (!key || !em || !sig) return -1;
    size_t k = key->n_limbs;
    if (k == 0 || em_len != key->n_len || sig_len != key->n_len) return -1;

    uint64_t s[PW_RSA_MAX_LIMBS], one[PW_RSA_MAX_LIMBS];
    uint64_t base_m[PW_RSA_MAX_LIMBS], acc[PW_RSA_MAX_LIMBS], tmp[PW_RSA_MAX_LIMBS];
    memset(s, 0, sizeof(s));
    memset(one, 0, sizeof(one));
    memset(base_m, 0, sizeof(base_m));
    memset(acc, 0, sizeof(acc));
    memset(tmp, 0, sizeof(tmp));

    be_to_limbs(sig, sig_len, s, k);
    if (limbs_cmp(s, key->n, k) >= 0) return -2;
    one[0] = 1;

    /* acc = 1*R mod n, base_m = sig*R mod n */
    mont_mul(base_m, s, key->r2, key->n, key->n0_inv, k);
    mont_mul(acc, one, key->r2, key->n, key->n0_inv, k);

    /* e = 65537 = 2^16 + 1 (binary: 1_0000_0000_0000_0001)
     * bit 16 (MSB): multiply by base */
    mont_mul(tmp, acc, base_m, key->n, key->n0_inv, k);
    memcpy(acc, tmp, k * sizeof(uint64_t));
    /* bits 15..0: square 16 times */
    for (int i = 0; i < 16; i++) {
        mont_mul(tmp, acc, acc, key->n, key->n0_inv, k);
        memcpy(acc, tmp, k * sizeof(uint64_t));
    }
    /* bit 0 is 1: multiply by base */
    mont_mul(tmp, acc, base_m, key->n, key->n0_inv, k);
    memcpy(acc, tmp, k * sizeof(uint64_t));

    /* out of Montgomery domain */
    mont_mul(tmp, acc, one, key->n, key->n0_inv, k);

    /* Convert back to big-endian and compare */
    uint8_t check[PW_RSA_MAX_BITS / 8];
    limbs_to_be(tmp, key->n_len, check);
    if (memcmp(check, em, em_len) != 0) {
        secure_zero(s, sizeof(s));
        secure_zero(one, sizeof(one));
        secure_zero(base_m, sizeof(base_m));
        secure_zero(acc, sizeof(acc));
        secure_zero(tmp, sizeof(tmp));
        secure_zero(check, sizeof(check));
        return -3;
    }
    secure_zero(s, sizeof(s));
    secure_zero(one, sizeof(one));
    secure_zero(base_m, sizeof(base_m));
    secure_zero(acc, sizeof(acc));
    secure_zero(tmp, sizeof(tmp));
    secure_zero(check, sizeof(check));
    return 0;
}

void limbs_to_be_diag(const uint64_t* limbs, size_t n_len, uint8_t* out) {
    limbs_to_be(limbs, n_len, out);
}
