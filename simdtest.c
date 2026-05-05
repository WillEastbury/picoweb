#include "simd.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

static int failures = 0;

static void check_lower(const char* in, const char* expect) {
    char buf[256];
    size_t n = strlen(in);
    memcpy(buf, in, n + 1);
    metal_lower_simd(buf, n);
    if (memcmp(buf, expect, n) != 0) {
        printf("LOWER FAIL: in=\"%s\" got=\"%.*s\" want=\"%s\"\n",
               in, (int)n, buf, expect);
        failures++;
    }
}

static void check_lower_bytes(const unsigned char* in, size_t n,
                              const unsigned char* expect) {
    unsigned char buf[256];
    memcpy(buf, in, n);
    metal_lower_simd((char*)buf, n);
    if (memcmp(buf, expect, n) != 0) {
        printf("LOWER BYTES FAIL (n=%zu)\n", n);
        for (size_t i = 0; i < n; i++)
            printf("  [%zu] got=%02x want=%02x\n", i, buf[i], expect[i]);
        failures++;
    }
}

static void check_eq(const char* a, const char* b, size_t n, bool want) {
    bool got = metal_eq_n(a, b, n);
    if (got != want) {
        printf("EQ FAIL: n=%zu a=\"%.*s\" b=\"%.*s\" got=%d want=%d\n",
               n, (int)n, a, (int)n, b, got, want);
        failures++;
    }
}

int main(void) {
    /* lower: empty, sub-16, exactly 16, > 16 with tail */
    check_lower("", "");
    check_lower("Hello", "hello");
    check_lower("ABCDEFGHIJKLMNOP", "abcdefghijklmnop");        /* exactly 16 */
    check_lower("ABCDEFGHIJKLMNOPQ", "abcdefghijklmnopq");      /* 16+1 */
    check_lower("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPxyz",
                "abcdefghijklmnopabcdefghijklmnopxyz");          /* 32+3 */

    /* boundary chars left alone: '@' (0x40), '[' (0x5b) */
    check_lower("@AZ[abcdefghijklmnop",
                "@az[abcdefghijklmnop");

    /* digits / punctuation untouched */
    check_lower("Host: WWW.Example.COM:8080",
                "host: www.example.com:8080");

    /* high-bit bytes untouched */
    {
        unsigned char in[20]  = {'A','B',0xff,0x80,0xc3,0xa9,'C','D',
                                 'E','F','G','H','I','J','K','L','M','N','O','P'};
        unsigned char want[20]= {'a','b',0xff,0x80,0xc3,0xa9,'c','d',
                                 'e','f','g','h','i','j','k','l','m','n','o','p'};
        check_lower_bytes(in, 20, want);
    }

    /* eq: empty, sub-16, exactly 16, > 16 mismatch in head/mid/tail */
    check_eq("", "", 0, true);
    check_eq("abc", "abc", 3, true);
    check_eq("abc", "abd", 3, false);
    check_eq("0123456789abcdef", "0123456789abcdef", 16, true);   /* exactly 16 */
    check_eq("0123456789abcdef", "0123456789abcdeF", 16, false);  /* tail diff */
    check_eq("X123456789abcdef", "0123456789abcdef", 16, false);  /* head diff */
    check_eq("0123456789abcdefGGGG", "0123456789abcdefGGGG", 20, true);
    check_eq("0123456789abcdefGGGG", "0123456789abcdefGGGX", 20, false);
    check_eq("0123456789abcdef0123456789abcdef",
             "0123456789abcdef0123456789abcdef", 32, true);
    check_eq("0123456789abcdef0123456789abcdef",
             "0123456789abcdef0123456789abcdeg", 32, false);
    /* 32-byte SIMD-only check, mid-block diff in 2nd 16B */
    check_eq("0123456789abcdef0X23456789abcdef",
             "0123456789abcdef0123456789abcdef", 32, false);

    /* SIMD active variant */
    printf("simd=%s, %d failure(s)\n", metal_simd_describe(), failures);
    return failures ? 1 : 0;
}
