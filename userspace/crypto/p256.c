#include "p256.h"

#include <string.h>

#include "util.h"

__extension__ typedef unsigned __int128 uint128_t;
__extension__ typedef signed __int128 int128_t;
typedef struct { uint64_t v[4]; } u256;
typedef struct { u256 x, y, z; uint64_t inf; } p256_point;

static const u256 P256_P = {{
    UINT64_C(0xffffffffffffffff), UINT64_C(0x00000000ffffffff),
    UINT64_C(0x0000000000000000), UINT64_C(0xffffffff00000001)
}};
static const u256 P256_N = {{
    UINT64_C(0xf3b9cac2fc632551), UINT64_C(0xbce6faada7179e84),
    UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffff00000000)
}};
static const u256 P256_B = {{
    UINT64_C(0x3bce3c3e27d2604b), UINT64_C(0x651d06b0cc53b0f6),
    UINT64_C(0xb3ebbd55769886bc), UINT64_C(0x5ac635d8aa3a93e7)
}};
static const struct { u256 x, y; } P256_G_TABLE[16] = {
    {{{UINT64_C(0xf4a13945d898c296), UINT64_C(0x77037d812deb33a0), UINT64_C(0xf8bce6e563a440f2), UINT64_C(0x6b17d1f2e12c4247)}},
     {{UINT64_C(0xcbb6406837bf51f5), UINT64_C(0x2bce33576b315ece), UINT64_C(0x8ee7eb4a7c0f9e16), UINT64_C(0x4fe342e2fe1a7f9b)}}},
    {{{UINT64_C(0xa60b48fc47669978), UINT64_C(0xc08969e277f21b35), UINT64_C(0x8a52380304b51ac3), UINT64_C(0x7cf27b188d034f7e)}},
     {{UINT64_C(0x9e04b79d227873d1), UINT64_C(0xba7dade63ce98229), UINT64_C(0x293d9ac69f7430db), UINT64_C(0x07775510db8ed040)}}},
    {{{UINT64_C(0xfb41661bc6e7fd6c), UINT64_C(0xe6c6b721efada985), UINT64_C(0xc8f7ef951d4bf165), UINT64_C(0x5ecbe4d1a6330a44)}},
     {{UINT64_C(0x9a79b127a27d5032), UINT64_C(0xd82ab036384fb83d), UINT64_C(0x374b06ce1a64a2ec), UINT64_C(0x8734640c4998ff7e)}}},
    {{{UINT64_C(0x509302446b030852), UINT64_C(0x031fe2db785596ef), UINT64_C(0xa02dde659ee62bd0), UINT64_C(0xe2534a3532d08fbb)}},
     {{UINT64_C(0x5c42c23f184ed8c6), UINT64_C(0x4efc96c3f30ee005), UINT64_C(0x19dfee5fda862d76), UINT64_C(0xe0f1575a4c633cc7)}}},
    {{{UINT64_C(0x21554a0dc3d033ed), UINT64_C(0xef8c82fd1f5be524), UINT64_C(0xd784c85608668fdf), UINT64_C(0x51590b7a515140d2)}},
     {{UINT64_C(0xd1d0bb44fda16da4), UINT64_C(0x0d012f00d4d80888), UINT64_C(0x8ae1bf36bf8a7926), UINT64_C(0xe0c17da8904a727d)}}},
    {{{UINT64_C(0xc6b0aae93c2291a9), UINT64_C(0x024c740debb215b4), UINT64_C(0x92d3242cb897dde3), UINT64_C(0xb01a172a76a4602c)}},
     {{UINT64_C(0xfd7c48538fc77fe2), UINT64_C(0x1c00f7701c7e16bd), UINT64_C(0x6fec0e2dfba70379), UINT64_C(0xe85c10743237dad5)}}},
    {{{UINT64_C(0x300628703187b2a3), UINT64_C(0x7ef9f8b8a80fef5b), UINT64_C(0x25bb30667c01fb60), UINT64_C(0x8e533b6fa0bf7b46)}},
     {{UINT64_C(0xc55e1a86c1f400b4), UINT64_C(0x53c73633cb041b21), UINT64_C(0x6d069f83a6f59000), UINT64_C(0x73eb1dbde0331836)}}},
    {{{UINT64_C(0xb4dd9dc1db6fb393), UINT64_C(0xc1d238980fce97db), UINT64_C(0x4042742d3ab54cad), UINT64_C(0x62d9779dbee9b053)}},
     {{UINT64_C(0xda540a6a0f09957e), UINT64_C(0xa2ed51f6bbe76a78), UINT64_C(0x4ff15d771167cee0), UINT64_C(0xad5accbd91e9d824)}}},
    {{{UINT64_C(0xd79e8a4b90949ee0), UINT64_C(0x9e0acb8c2c6df8b3), UINT64_C(0x878938d51d71f872), UINT64_C(0xea68d7b6fedf0b71)}},
     {{UINT64_C(0xe85a224a4dd048fa), UINT64_C(0x4d714feaa4de823f), UINT64_C(0x87014a964a8ea0c8), UINT64_C(0x2a2744c972c9fce7)}}},
    {{{UINT64_C(0x4c36069404c5723f), UINT64_C(0x45ca6c471c48306e), UINT64_C(0x591214d1ea223fb5), UINT64_C(0xcef66d6b2a3a993e)}},
     {{UINT64_C(0xca34bbaa44af0773), UINT64_C(0x590ded29fe751eee), UINT64_C(0x6e123cdd9d3b4c10), UINT64_C(0x878662a229aaae90)}}},
    {{{UINT64_C(0x433391d374bc21d1), UINT64_C(0x16742ed0255048bf), UINT64_C(0x0638379db0c21cda), UINT64_C(0x3ed113b7883b4c59)}},
     {{UINT64_C(0xe2f8eefce82a3740), UINT64_C(0x090d04da5e9889da), UINT64_C(0x24c843afa4f4c68a), UINT64_C(0x9099209accc4c8a2)}}},
    {{{UINT64_C(0xd500c5ee8624e3c4), UINT64_C(0x79983028b2f82c99), UINT64_C(0x4626537320e5d551), UINT64_C(0x741dd5bda817d95e)}},
     {{UINT64_C(0x1995ff22cd4481d3), UINT64_C(0x8eeb912c35ba5ca7), UINT64_C(0x567383554887b154), UINT64_C(0x0770b46a9c385fdc)}}},
    {{{UINT64_C(0x98e15d9d46072c01), UINT64_C(0x792e284b65ead58a), UINT64_C(0x61805df2d85ee2fc), UINT64_C(0x177c837ae0ac495a)}},
     {{UINT64_C(0x9c43bbe2efc7bfd8), UINT64_C(0x26ee14c3a1fb4df3), UINT64_C(0xa24091adb40f4e72), UINT64_C(0x63bb58cd4ebea558)}}},
    {{{UINT64_C(0x5709277324d2920b), UINT64_C(0xf126acbe7a069c5e), UINT64_C(0x7a76647f4336df3c), UINT64_C(0x54e77a001c3862b9)}},
     {{UINT64_C(0x1ba7c82f60d0b375), UINT64_C(0x7171ea7773509008), UINT64_C(0x42121f8c05a2e7c3), UINT64_C(0xf599f1bb29f43175)}}},
    {{{UINT64_C(0x63668c63e59b9d5f), UINT64_C(0xae03af92de3a0ef1), UINT64_C(0xadfb378999888265), UINT64_C(0xf0454dc6971abae7)}},
     {{UINT64_C(0x47e59cde0d034f36), UINT64_C(0x2a3b21ce75b5fa3f), UINT64_C(0x4e6594e51f9643e6), UINT64_C(0xb5b93ee3592e2d1f)}}},
    {{{UINT64_C(0xa5eb4787e1277c6e), UINT64_C(0xcd28392eff6ca038), UINT64_C(0x8b821c629836315f), UINT64_C(0x76a94d138a6b4185)}},
     {{UINT64_C(0x0e9ddd724b8c5110), UINT64_C(0x8599a0040fc78baa), UINT64_C(0x6cb0a1b5e11e8720), UINT64_C(0xa985fe61341f260e)}}}
};

static uint64_t ct_is_zero_u64(uint64_t x) { return ((x | (0u - x)) >> 63) ^ 1u; }
static uint64_t ct_mask(uint64_t bit) { return 0u - (bit & 1u); }

static uint64_t u256_is_zero(const u256* a) {
    return ct_is_zero_u64(a->v[0] | a->v[1] | a->v[2] | a->v[3]);
}

static uint64_t u256_eq(const u256* a, const u256* b) {
    return ct_is_zero_u64((a->v[0] ^ b->v[0]) | (a->v[1] ^ b->v[1]) |
                          (a->v[2] ^ b->v[2]) | (a->v[3] ^ b->v[3]));
}

static void u256_cmov(u256* r, const u256* a, uint64_t bit) {
    uint64_t m = ct_mask(bit);
    for (int i = 0; i < 4; i++) r->v[i] = (r->v[i] & ~m) | (a->v[i] & m);
}

static void point_cmov(p256_point* r, const p256_point* a, uint64_t bit) {
    u256_cmov(&r->x, &a->x, bit);
    u256_cmov(&r->y, &a->y, bit);
    u256_cmov(&r->z, &a->z, bit);
    uint64_t m = ct_mask(bit);
    r->inf = (r->inf & ~m) | (a->inf & m);
}

static uint64_t u256_add_raw(u256* r, const u256* a, const u256* b) {
    uint128_t c = 0;
    for (int i = 0; i < 4; i++) {
        c += (uint128_t)a->v[i] + b->v[i];
        r->v[i] = (uint64_t)c;
        c >>= 64;
    }
    return (uint64_t)c;
}

static uint64_t u256_sub_raw(u256* r, const u256* a, const u256* b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t bi = b->v[i];
        uint64_t ri = a->v[i] - bi - borrow;
        uint64_t b1 = (a->v[i] < bi) ? 1u : 0u;
        uint64_t b2 = (borrow && a->v[i] == bi) ? 1u : 0u;
        r->v[i] = ri;
        borrow = b1 | b2;
    }
    return borrow;
}

static uint64_t u256_ge(const u256* a, const u256* b) {
    u256 tmp;
    return u256_sub_raw(&tmp, a, b) ^ 1u;
}

static void mod_add(u256* r, const u256* a, const u256* b, const u256* m) {
    u256 s, t;
    uint64_t carry = u256_add_raw(&s, a, b);
    uint64_t borrow = u256_sub_raw(&t, &s, m);
    uint64_t use_s = borrow & (carry ^ 1u);
    *r = t;
    u256_cmov(r, &s, use_s);
}

static void mod_sub(u256* r, const u256* a, const u256* b, const u256* m) {
    u256 d, s;
    uint64_t borrow = u256_sub_raw(&d, a, b);
    (void)u256_add_raw(&s, &d, m);
    *r = d;
    u256_cmov(r, &s, borrow);
}

static uint128_t mul_add_u64(uint64_t* r, uint64_t a, uint64_t b, uint128_t carry) {
    uint128_t c = (uint128_t)a * b + *r + carry;
    *r = (uint64_t)c;
    return c >> 64;
}

static void normalize32(int128_t a[31], int n) {
    for (int i = 0; i < n; i++) {
        int128_t old = a[i];
        uint32_t rem = (uint32_t)old;
        a[i] = rem;
        a[i + 1] += (old - (int128_t)rem) >> 32;
    }
}

static void mod_mul(u256* r, const u256* a, const u256* b, const u256* m) {
    (void)m;
    uint64_t prod[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        uint128_t carry = 0;
        for (int j = 0; j < 4; j++) carry = mul_add_u64(&prod[i + j], a->v[i], b->v[j], carry);
        for (int k = i + 4; k < 8; k++) {
            uint128_t c = (uint128_t)prod[k] + carry;
            prod[k] = (uint64_t)c;
            carry = c >> 64;
        }
    }

    int128_t acc[31] = {0};
    for (int i = 0; i < 8; i++) {
        acc[2 * i] = (uint32_t)prod[i];
        acc[2 * i + 1] = (uint32_t)(prod[i] >> 32);
    }

    for (int pass = 0; pass < 9; pass++) {
        int max = 15 - pass;
        if (max < 8) max = 8;
        for (int i = 8; i <= max; i++) {
            int128_t h = acc[i];
            acc[i] = 0;
            acc[i - 8] += h;
            acc[i - 5] -= h;
            acc[i - 2] -= h;
            acc[i - 1] += h;
        }
        normalize32(acc, max + 1);
    }

    for (int i = 0; i < 4; i++) {
        r->v[i] = (uint64_t)acc[2 * i] | ((uint64_t)acc[2 * i + 1] << 32);
    }

    u256 sub;
    uint64_t borrow = u256_sub_raw(&sub, r, &P256_P);
    u256_cmov(r, &sub, borrow ^ 1u);
}

static void fe_add(u256* r, const u256* a, const u256* b) { mod_add(r, a, b, &P256_P); }
static void fe_sub(u256* r, const u256* a, const u256* b) { mod_sub(r, a, b, &P256_P); }
static void fe_mul(u256* r, const u256* a, const u256* b) { mod_mul(r, a, b, &P256_P); }
static void fe_sqr(u256* r, const u256* a) { mod_mul(r, a, a, &P256_P); }

static void fe_from_u64(u256* r, uint64_t x) { r->v[0] = x; r->v[1] = r->v[2] = r->v[3] = 0; }

static void fe_inv(u256* r, const u256* a) {
    static const u256 exp = {{
        UINT64_C(0xfffffffffffffffd), UINT64_C(0x00000000ffffffff),
        UINT64_C(0x0000000000000000), UINT64_C(0xffffffff00000001)
    }};
    u256 z; fe_from_u64(&z, 1);
    for (int i = 255; i >= 0; i--) {
        fe_sqr(&z, &z);
        if ((exp.v[i / 64] >> (i % 64)) & 1u) fe_mul(&z, &z, a);
    }
    *r = z;
}

static int u256_from_be_checked(u256* r, const uint8_t in[32], const u256* m) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++) w = (w << 8) | in[(3 - i) * 8 + j];
        r->v[i] = w;
    }
    if (u256_is_zero(r) || u256_ge(r, m)) return -1;
    return 0;
}

static int fe_from_be(u256* r, const uint8_t in[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++) w = (w << 8) | in[(3 - i) * 8 + j];
        r->v[i] = w;
    }
    if (u256_ge(r, &P256_P)) return -1;
    return 0;
}

static void u256_to_be(const u256* a, uint8_t out[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = a->v[3 - i];
        for (int j = 0; j < 8; j++) out[i * 8 + j] = (uint8_t)(w >> (56 - 8 * j));
    }
}

static void point_inf(p256_point* p) {
    memset(p, 0, sizeof(*p));
    p->inf = 1;
}

static void point_from_affine(p256_point* p, const u256* x, const u256* y) {
    p->x = *x;
    p->y = *y;
    fe_from_u64(&p->z, 1);
    p->inf = 0;
}

static void point_select_base(p256_point* r, uint64_t idx) {
    point_inf(r);
    for (uint64_t i = 1; i <= 16; i++) {
        p256_point t;
        point_from_affine(&t, &P256_G_TABLE[i - 1].x, &P256_G_TABLE[i - 1].y);
        point_cmov(r, &t, ct_is_zero_u64(idx ^ i));
    }
}

static void point_double(p256_point* r, const p256_point* p) {
    u256 xx, yy, yyyy, zz, zz2, s, m, t, tmp1, tmp2, x3, y3, z3;
    fe_sqr(&xx, &p->x);
    fe_sqr(&yy, &p->y);
    fe_sqr(&yyyy, &yy);
    fe_sqr(&zz, &p->z);
    fe_sqr(&zz2, &zz);
    fe_add(&tmp1, &p->x, &yy);
    fe_sqr(&tmp1, &tmp1);
    fe_sub(&tmp1, &tmp1, &xx);
    fe_sub(&tmp1, &tmp1, &yyyy);
    fe_add(&s, &tmp1, &tmp1);
    fe_sub(&tmp1, &xx, &zz2);
    fe_add(&m, &tmp1, &tmp1);
    fe_add(&m, &m, &tmp1);
    fe_sqr(&t, &m);
    fe_add(&tmp1, &s, &s);
    fe_sub(&x3, &t, &tmp1);
    fe_sub(&tmp1, &s, &x3);
    fe_mul(&y3, &m, &tmp1);
    fe_add(&tmp2, &yyyy, &yyyy);
    fe_add(&tmp2, &tmp2, &tmp2);
    fe_add(&tmp2, &tmp2, &tmp2);
    fe_sub(&y3, &y3, &tmp2);
    fe_add(&tmp1, &p->y, &p->z);
    fe_sqr(&tmp1, &tmp1);
    fe_sub(&tmp1, &tmp1, &yy);
    fe_sub(&z3, &tmp1, &zz);
    r->x = x3; r->y = y3; r->z = z3;
    r->inf = p->inf | u256_is_zero(&p->y);
}

static void point_add(p256_point* r, const p256_point* p, const p256_point* q) {
    u256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v;
    u256 tmp1, tmp2, x3, y3, z3;
    fe_sqr(&z1z1, &p->z);
    fe_sqr(&z2z2, &q->z);
    fe_mul(&u1, &p->x, &z2z2);
    fe_mul(&u2, &q->x, &z1z1);
    fe_mul(&tmp1, &q->z, &z2z2);
    fe_mul(&s1, &p->y, &tmp1);
    fe_mul(&tmp1, &p->z, &z1z1);
    fe_mul(&s2, &q->y, &tmp1);
    fe_sub(&h, &u2, &u1);
    fe_add(&tmp1, &h, &h);
    fe_sqr(&i, &tmp1);
    fe_mul(&j, &h, &i);
    fe_sub(&tmp1, &s2, &s1);
    fe_add(&rr, &tmp1, &tmp1);
    fe_mul(&v, &u1, &i);
    fe_sqr(&x3, &rr);
    fe_sub(&x3, &x3, &j);
    fe_add(&tmp1, &v, &v);
    fe_sub(&x3, &x3, &tmp1);
    fe_sub(&tmp1, &v, &x3);
    fe_mul(&y3, &rr, &tmp1);
    fe_mul(&tmp2, &s1, &j);
    fe_add(&tmp2, &tmp2, &tmp2);
    fe_sub(&y3, &y3, &tmp2);
    fe_add(&tmp1, &p->z, &q->z);
    fe_sqr(&tmp1, &tmp1);
    fe_sub(&tmp1, &tmp1, &z1z1);
    fe_sub(&tmp1, &tmp1, &z2z2);
    fe_mul(&z3, &tmp1, &h);

    p256_point add = {x3, y3, z3, 0};
    p256_point dbl;
    point_double(&dbl, p);
    p256_point inf;
    point_inf(&inf);

    uint64_t hzero = u256_is_zero(&h);
    uint64_t rzero = u256_is_zero(&tmp1); /* overwritten below intentionally avoided */
    fe_sub(&tmp1, &s2, &s1);
    rzero = u256_is_zero(&tmp1);

    *r = add;
    point_cmov(r, &dbl, hzero & rzero);
    point_cmov(r, &inf, hzero & (rzero ^ 1u));
    point_cmov(r, q, p->inf);
    point_cmov(r, p, q->inf);
}

static void point_add_affine(p256_point* r, const p256_point* p, const p256_point* q) {
    u256 z1z1, u2, s2, h, i, j, rr, v;
    u256 tmp1, tmp2, x3, y3, z3;
    fe_sqr(&z1z1, &p->z);
    fe_mul(&u2, &q->x, &z1z1);
    fe_mul(&tmp1, &p->z, &z1z1);
    fe_mul(&s2, &q->y, &tmp1);
    fe_sub(&h, &u2, &p->x);
    fe_add(&tmp1, &h, &h);
    fe_sqr(&i, &tmp1);
    fe_mul(&j, &h, &i);
    fe_sub(&tmp1, &s2, &p->y);
    fe_add(&rr, &tmp1, &tmp1);
    fe_mul(&v, &p->x, &i);
    fe_sqr(&x3, &rr);
    fe_sub(&x3, &x3, &j);
    fe_add(&tmp1, &v, &v);
    fe_sub(&x3, &x3, &tmp1);
    fe_sub(&tmp1, &v, &x3);
    fe_mul(&y3, &rr, &tmp1);
    fe_mul(&tmp2, &p->y, &j);
    fe_add(&tmp2, &tmp2, &tmp2);
    fe_sub(&y3, &y3, &tmp2);
    fe_add(&tmp1, &p->z, &h);
    fe_sqr(&tmp1, &tmp1);
    fe_sub(&tmp1, &tmp1, &z1z1);
    fe_sqr(&tmp2, &h);
    fe_sub(&z3, &tmp1, &tmp2);

    p256_point add = {x3, y3, z3, 0};
    p256_point dbl;
    point_double(&dbl, p);
    p256_point inf;
    point_inf(&inf);

    uint64_t hzero = u256_is_zero(&h);
    fe_sub(&tmp1, &s2, &p->y);
    uint64_t rzero = u256_is_zero(&tmp1);

    *r = add;
    point_cmov(r, &dbl, hzero & rzero);
    point_cmov(r, &inf, hzero & (rzero ^ 1u));
    point_cmov(r, q, p->inf);
    point_cmov(r, p, q->inf);
}

static void point_to_affine(const p256_point* p, u256* x, u256* y) {
    u256 zi, z2, z3;
    fe_inv(&zi, &p->z);
    fe_sqr(&z2, &zi);
    fe_mul(&z3, &z2, &zi);
    fe_mul(x, &p->x, &z2);
    fe_mul(y, &p->y, &z3);
}

static uint64_t scalar_nibble(const u256* k, int pos) {
    return (k->v[pos / 16] >> ((pos % 16) * 4)) & 0xfu;
}

static void point_select(p256_point* r, const p256_point table[16], uint64_t idx) {
    point_inf(r);
    for (uint64_t i = 0; i < 16; i++) point_cmov(r, &table[i], ct_is_zero_u64(idx ^ i));
}

static int scalar_mul_window_u256(const p256_point* p, const u256* k, u256* x, u256* y) {
    p256_point table[16];
    point_inf(&table[0]);
    table[1] = *p;
    for (int i = 2; i < 16; i++) point_add(&table[i], &table[i - 1], p);

    p256_point r;
    point_inf(&r);
    for (int pos = 63; pos >= 0; pos--) {
        for (int i = 0; i < 4; i++) point_double(&r, &r);
        p256_point t, a;
        point_select(&t, table, scalar_nibble(k, pos));
        point_add(&a, &r, &t);
        r = a;
    }
    if (r.inf) return -1;
    point_to_affine(&r, x, y);
    return 0;
}

static int scalar_mul_base_u256(const u256* k, u256* x, u256* y) {
    p256_point r;
    point_inf(&r);
    for (int pos = 63; pos >= 0; pos--) {
        for (int i = 0; i < 4; i++) point_double(&r, &r);
        p256_point t, a;
        point_select_base(&t, scalar_nibble(k, pos));
        point_add_affine(&a, &r, &t);
        r = a;
    }
    if (r.inf) return -1;
    point_to_affine(&r, x, y);
    return 0;
}

int p256_scalar_mul_base(const uint8_t scalar[32], uint8_t out_xy[64]) {
    if (!scalar || !out_xy) return -1;
    u256 k, x, y;
    if (u256_from_be_checked(&k, scalar, &P256_N) != 0) return -1;
    if (scalar_mul_base_u256(&k, &x, &y) != 0) return -1;
    u256_to_be(&x, out_xy);
    u256_to_be(&y, out_xy + 32);
    secure_zero(&k, sizeof(k));
    return 0;
}

int p256_pubkey_validate(const uint8_t in[65]) {
    if (!in || in[0] != 0x04) return -1;
    u256 x, y, lhs, rhs, tmp;
    if (fe_from_be(&x, in + 1) != 0 || fe_from_be(&y, in + 33) != 0) return -1;
    if (u256_is_zero(&x) || u256_is_zero(&y)) return -1;
    fe_sqr(&lhs, &y);
    fe_sqr(&rhs, &x);
    fe_mul(&rhs, &rhs, &x);
    fe_add(&tmp, &x, &x);
    fe_add(&tmp, &tmp, &x);
    fe_sub(&rhs, &rhs, &tmp);
    fe_add(&rhs, &rhs, &P256_B);
    if (!u256_eq(&lhs, &rhs)) return -1;

    p256_point q;
    point_from_affine(&q, &x, &y);
    u256 ox, oy;
    return scalar_mul_window_u256(&q, &P256_N, &ox, &oy) != 0 ? 0 : -1;
}

int p256_derive_pubkey(const uint8_t scalar[32], uint8_t out_pub[65]) {
    if (!out_pub) return -1;
    out_pub[0] = 0x04;
    return p256_scalar_mul_base(scalar, out_pub + 1);
}
