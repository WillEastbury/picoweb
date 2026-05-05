/*
 * Per-worker buffer pool implementation.
 *
 * The free list is threaded through the unused slots: the first
 * 4 bytes of each free slot hold the index of the next free slot
 * (or `slot_count` to indicate end-of-list). free_head points at
 * the head, or slot_count if exhausted.
 *
 * pool_rent is O(1) — three loads, one store. No branching beyond
 * the empty check.
 */

#include "pool.h"

#include <string.h>

#define POOL_TERM 0xffffffffu

int pool_init(buffer_pool_t* p, void* storage,
              uint32_t slot_size, uint32_t slot_count) {
    if (!p || !storage)            return -1;
    if (slot_size < sizeof(uint32_t)) return -1;
    if (slot_count == 0)           return -1;
    if (slot_count >= POOL_TERM)   return -1;          /* reserve sentinel */

    p->slabs = (uint8_t*)storage;
    p->slot_size = slot_size;
    p->slot_count = slot_count;
    p->in_use = 0;
    p->high_water = 0;
    p->exhaustion_count = 0;
    p->total_rents = 0;

    /* Build the free list: 0 -> 1 -> 2 -> ... -> n-1 -> TERM. */
    for (uint32_t i = 0; i + 1 < slot_count; i++) {
        uint32_t* next = (uint32_t*)(p->slabs + (size_t)i * slot_size);
        *next = i + 1;
    }
    uint32_t* tail = (uint32_t*)(p->slabs + (size_t)(slot_count - 1) * slot_size);
    *tail = POOL_TERM;
    p->free_head = 0;

    return 0;
}

void* pool_rent(buffer_pool_t* p) {
    if (p->free_head == POOL_TERM) {
        p->exhaustion_count++;
        return NULL;
    }
    uint32_t idx = p->free_head;
    uint8_t* slot = p->slabs + (size_t)idx * p->slot_size;
    p->free_head = *(uint32_t*)slot;
    p->in_use++;
    if (p->in_use > p->high_water) p->high_water = p->in_use;
    p->total_rents++;
    return slot;
}

void pool_release(buffer_pool_t* p, void* slot) {
    if (!slot) return;
    uint8_t* s = (uint8_t*)slot;
    /* Compute slot index from offset; relies on slot_size dividing
     * the offset cleanly, which is true by construction. */
    size_t off = (size_t)(s - p->slabs);
    uint32_t idx = (uint32_t)(off / p->slot_size);
    *(uint32_t*)s = p->free_head;
    p->free_head = idx;
    p->in_use--;
}
