#include "arena.h"
#include "util.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t page_size_cached(void) {
    static size_t ps = 0;
    if (!ps) ps = (size_t)sysconf(_SC_PAGESIZE);
    return ps;
}

bool arena_init(arena_t* a, size_t cap_bytes) {
    size_t ps = page_size_cached();
    size_t cap = metal_align_up(cap_bytes, ps);
    if (cap == 0) cap = ps;
    /* MAP_POPULATE prefaults every page so the first response on the
     * hot path never takes a minor page fault. Free latency win. */
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_POPULATE
    flags |= MAP_POPULATE;
#endif
    void* p = mmap(NULL, cap, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) return false;
#ifdef MADV_HUGEPAGE
    /* Hint THP. Kernel will promote to 2MB pages when alignment
     * permits, eliminating TLB walks on body access. Best-effort —
     * we don't care if the kernel ignores it. */
    (void)madvise(p, cap, MADV_HUGEPAGE);
#endif
    a->base = (char*)p;
    a->cap = cap;
    a->off = 0;
    a->frozen = false;
    return true;
}

void* arena_alloc(arena_t* a, size_t len, size_t align) {
    if (a->frozen) {
        metal_die("arena_alloc after freeze (programmer error)");
    }
    if (align == 0) align = 1;
    size_t aligned_off = metal_align_up(a->off, align);
    if (aligned_off + len < aligned_off || aligned_off + len > a->cap) {
        metal_die("arena out of capacity: need %zu at off %zu (cap %zu)",
                  len, aligned_off, a->cap);
    }
    void* out = a->base + aligned_off;
    a->off = aligned_off + len;
    return out;
}

void* arena_dup(arena_t* a, const void* src, size_t len) {
    void* dst = arena_alloc(a, len, 8);
    memcpy(dst, src, len);
    return dst;
}

const char* arena_strdup_n(arena_t* a, const char* s, size_t len, bool include_nul) {
    size_t total = include_nul ? len + 1 : len;
    char* dst = (char*)arena_alloc(a, total, 1);
    memcpy(dst, s, len);
    if (include_nul) dst[len] = '\0';
    return dst;
}

bool arena_freeze(arena_t* a) {
    if (a->frozen) return true;
    if (mprotect(a->base, a->cap, PROT_READ) != 0) {
        metal_log("mprotect(PROT_READ) failed: %s", strerror(errno));
        return false;
    }
    a->frozen = true;
    return true;
}
