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
bool   arena_freeze(arena_t* a);
static inline size_t arena_used(const arena_t* a) { return a->off; }

#endif
