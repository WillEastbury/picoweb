#include "util.h"
#include "simd.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void metal_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void metal_die(const char* fmt, ...) {
    int saved_errno = errno;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (saved_errno) {
        fprintf(stderr, ": %s", strerror(saved_errno));
    }
    fputc('\n', stderr);
    exit(1);
}

int64_t metal_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint64_t metal_fnv1a_init(void) { return 1469598103934665603ULL; }

uint64_t metal_fnv1a_step(uint64_t h, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t metal_fnv1a_step_lower(uint64_t h, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = p[i];
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32);
        h ^= b;
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t metal_fnv1a(const void* data, size_t len) {
    return metal_fnv1a_step(metal_fnv1a_init(), data, len);
}

uint64_t metal_fnv1a_lower(const void* data, size_t len) {
    return metal_fnv1a_step_lower(metal_fnv1a_init(), data, len);
}

void metal_lower_inplace(char* buf, size_t len) {
    metal_lower_simd(buf, len);
}

bool metal_ieq(const char* a, size_t alen, const char* b, size_t blen) {
    if (alen != blen) return false;
    for (size_t i = 0; i < alen; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return false;
    }
    return true;
}

size_t metal_next_pow2(size_t n) {
    if (n < 2) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
#if SIZE_MAX > 0xFFFFFFFFu
    n |= n >> 32;
#endif
    return n + 1;
}
