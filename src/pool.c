#include "pool.h"
#include "util.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

bool pool_init(pool_t* p, size_t cap) {
    if (cap == 0) return false;
    size_t bytes = cap * sizeof(conn_t);
    void* mem = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return false;
#ifdef MADV_HUGEPAGE
    /* Pool can be tens of MB (cap × 8KB). With 4KB pages that's
     * thousands of TLB entries under heavy load — easily blowing
     * past the dTLB. THP collapses to 2MB pages and keeps the
     * working set TLB-resident. Best-effort hint. */
    (void)madvise(mem, bytes, MADV_HUGEPAGE);
#endif
#ifdef MADV_POPULATE_WRITE
    /* Pre-fault every page now so RSS at startup equals RSS under
     * peak load. Without this, anonymous mmap is demand-paged: the
     * init loop below only writes the first few bytes of each conn_t
     * (touching page 0 of each slot), so the 8 KiB read_buf and the
     * scratch in pages 1-2 stay unfaulted until a real connection
     * writes to them. That makes "preallocated" a lie at the RSS
     * level — idle RSS understates working set, and peak RSS climbs
     * the first time a burst arrives and never comes back down.
     * MADV_POPULATE_WRITE faults the whole range now, in one call.
     * Linux 5.14+; older kernels skip the hint and behave as before. */
    (void)madvise(mem, bytes, MADV_POPULATE_WRITE);
#endif
    /* Belt-and-braces: dirty every byte so even kernels that map
     * POPULATE_WRITE to the shared zero page give us real backing
     * pages. Cheap (a single linear pass at boot). */
    memset(mem, 0, bytes);
    /* Pin the whole pool into RAM. With CAP_IPC_LOCK we are immune to
     * swap and memory-pressure reclaim — RSS becomes a true ceiling,
     * not a high-water mark the kernel can erode. Without the cap,
     * mlock() returns EPERM/EAGAIN against the default 64KB
     * RLIMIT_MEMLOCK; we log once and continue (MADV_POPULATE_WRITE
     * still gave us residency, just not pinning). */
    if (mlock(mem, bytes) != 0) {
        metal_log("pool: mlock(%zu) failed: %s (add CAP_IPC_LOCK or raise "
                  "RLIMIT_MEMLOCK to pin the pool)", bytes, strerror(errno));
    }
    p->base = (conn_t*)mem;
    p->cap = cap;
    p->in_use = 0;

    /* Build free list: pool[0] -> pool[1] -> ... -> pool[cap-1] -> NULL */
    for (size_t i = 0; i < cap; i++) {
        p->base[i].fd = -1;
        p->base[i].next_free = (i + 1 < cap) ? &p->base[i + 1] : NULL;
    }
    p->free_head = &p->base[0];
    return true;
}

conn_t* pool_alloc(pool_t* p) {
    conn_t* c = p->free_head;
    if (!c) return NULL;
    p->free_head = c->next_free;
    c->next_free = NULL;
    p->in_use++;
    return c;
}

void pool_free(pool_t* p, conn_t* c) {
    c->fd = -1;
    c->res = NULL;
    c->seg_count = 0;
    c->bytes_sent = 0;
    c->read_off = 0;
    c->state = ST_READING;
    c->req_count = 0;
    c->peer_half_closed = false;
    c->close_after = false;
    c->send_body = false;
    c->req_start_tsc = 0;
    c->obs_route = METRICS_ROUTE_OTHER;
    c->obs_method = M_UNKNOWN;
    c->obs_status = 0;
    c->obs_request_bytes = 0;
    c->obs_response_bytes = 0;
    c->last_active_ms = 0;
    c->api_pending = false;
    c->api_method = M_UNKNOWN;
    c->api_headers_len = 0;
    c->api_body_needed = 0;
    c->api_cookie_len = 0;
    c->api_host_len = 0;
    c->api_origin_len = 0;
    c->api_acr_headers_len = 0;
    c->api_principal_len = 0;
    c->api_tenant_len = 0;
    c->api_has_pw_auth = false;
    c->api_path_len = 0;
    c->next_free = p->free_head;
    p->free_head = c;
    p->in_use--;
}
