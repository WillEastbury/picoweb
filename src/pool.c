#include "pool.h"
#include "util.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

bool pool_init(pool_t* p, size_t cap) {
    if (cap == 0) return false;
    size_t bytes = cap * sizeof(conn_t);
    void* mem = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return false;
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
    c->head_ptr = NULL;
    c->head_len = 0;
    c->bytes_sent = 0;
    c->read_off = 0;
    c->state = ST_READING;
    c->req_count = 0;
    c->peer_half_closed = false;
    c->close_after = false;
    c->send_body = false;
    c->req_start_tsc = 0;
    c->last_active_ms = 0;
    c->next_free = p->free_head;
    p->free_head = c;
    p->in_use--;
}
