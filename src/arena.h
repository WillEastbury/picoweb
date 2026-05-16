#ifndef METAL_ARENA_H
#define METAL_ARENA_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char*  base;
    size_t cap;
    size_t off;
    bool   frozen;
} arena_t;

bool   arena_init(arena_t* a, size_t cap_bytes);
void*  arena_alloc(arena_t* a, size_t len, size_t align);
void*  arena_dup(arena_t* a, const void* src, size_t len);
const char* arena_strdup_n(arena_t* a, const char* s, size_t len, bool include_nul);
/* Truncate the arena's backing mmap down to the page that holds the
 * current write offset, releasing the unused tail back to the kernel.
 * Must be called BEFORE arena_freeze. The shrink is in-place — base
 * pointer is unchanged, so existing pointers into the arena remain
 * valid. Safe no-op if there is no whole page to release. */
bool   arena_shrink_to_fit(arena_t* a);
bool   arena_freeze(arena_t* a);
static inline size_t arena_used(const arena_t* a) { return a->off; }

#endif
