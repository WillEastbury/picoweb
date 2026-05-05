#ifndef METAL_UTIL_H
#define METAL_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* Logging / fatal */
void metal_log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void metal_die(const char* fmt, ...) __attribute__((format(printf, 1, 2), noreturn));

/* Monotonic time in milliseconds */
int64_t metal_now_ms(void);

/* FNV-1a 64-bit hash over a sized byte range */
uint64_t metal_fnv1a(const void* data, size_t len);
/* FNV-1a 64-bit hash, lowercasing ASCII letters as it goes (for
 * case-insensitive hostname hashing). */
uint64_t metal_fnv1a_lower(const void* data, size_t len);

/* Incremental FNV-1a: start with metal_fnv1a_init() and update with
 * metal_fnv1a_step / _step_lower. Useful for keying on multiple
 * spans (e.g., host + separator + path) without concatenation. */
uint64_t metal_fnv1a_init(void);
uint64_t metal_fnv1a_step(uint64_t h, const void* data, size_t len);
uint64_t metal_fnv1a_step_lower(uint64_t h, const void* data, size_t len);

/* Bounds-checked in-place lowercase. */
void metal_lower_inplace(char* buf, size_t len);

/* Case-insensitive byte equality */
bool metal_ieq(const char* a, size_t alen, const char* b, size_t blen);

/* Round up to next power of two; minimum 1. */
size_t metal_next_pow2(size_t n);

/* Round up x to a multiple of align (align must be power of 2). */
static inline size_t metal_align_up(size_t x, size_t align) {
    return (x + (align - 1)) & ~(align - 1);
}

#endif
