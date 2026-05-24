#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* for mremap */
#endif

#include "arena.h"
#include "numa.h"
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
    /* NUMA: interleave the arena pages across all online nodes BEFORE
     * any first-touch (which MAP_POPULATE has already done — but mbind
     * with MPOL_MF_MOVE-less flags will still apply to subsequent
     * faults, and on multi-socket systems this dramatically reduces
     * cross-node response-body access for workers pinned on non-main
     * nodes). No-op on single-node systems. */
    (void)numa_interleave_all(p, cap);
#ifdef MADV_HUGEPAGE
    /* Hint THP. Kernel will promote to 2MB pages when alignment
     * permits, eliminating TLB walks on body access. Best-effort —
     * we don't care if the kernel ignores it. */
    (void)madvise(p, cap, MADV_HUGEPAGE);
#endif
    /* Pin the arena. Arena memory is the head/body/brotli bytes of
     * every response — the actual static-serving working set. Pinning
     * removes the kernel from the critical path entirely: no reclaim,
     * no swap-out, no minor faults from background memory pressure.
     * Best-effort; logs and continues without CAP_IPC_LOCK. */
    if (mlock(p, cap) != 0) {
        metal_log("arena: mlock(%zu) failed: %s (add CAP_IPC_LOCK or raise "
                  "RLIMIT_MEMLOCK to pin response bodies)", cap, strerror(errno));
    }
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

bool arena_shrink_to_fit(arena_t* a) {
    if (a->frozen) return true;
    size_t ps = page_size_cached();
    size_t new_cap = metal_align_up(a->off, ps);
    if (new_cap == 0) new_cap = ps;
    if (new_cap >= a->cap) return true;       /* nothing to release */
    /* Plain mremap (no MREMAP_MAYMOVE): a shrink is always in-place,
     * so base pointer stays valid and existing pointers into the
     * arena (chrome_t, slot keys, body bytes, ...) remain live. */
    void* p = mremap(a->base, a->cap, new_cap, 0);
    if (p == MAP_FAILED) {
        metal_log("arena_shrink_to_fit: mremap %zu -> %zu failed: %s",
                  a->cap, new_cap, strerror(errno));
        return false;
    }
    a->cap = new_cap;
    return true;
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
