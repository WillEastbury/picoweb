/*
 * Per-worker fixed-size buffer pool.
 *
 * picoweb's hard rule is: NO ALLOCATIONS AFTER STARTUP. This pool
 * provides "rent / release" semantics over a pre-allocated pile of
 * fixed-size slabs. All slots are allocated once at startup; the
 * pool itself is allocated on the worker arena (or static storage)
 * by the caller.
 *
 * The pool is intentionally NOT thread-safe — picoweb is share-
 * nothing per worker, so each worker holds its own pool and
 * rent/release happens on the same thread that owns the pool.
 *
 * Two separate pool sizes are typically wanted:
 *
 *   - SMALL slots: short-lived scratch for HKDF outputs, transcript
 *     hashes, key derivation intermediates. ~256 bytes is plenty.
 *
 *   - LARGE slots: full TLS record buffers (header + max-plaintext +
 *     padding + tag). One per active connection plus a few extra.
 *     Use `PW_RX_REASSEMBLY_SLOT` (from `tls/record.h`) as the
 *     slot_size so the pool can hold one wire-format TLS record
 *     without truncation.
 *
 * The pool tracks usage and high-water mark so operators can size
 * the slot count from observation rather than guesswork.
 *
 * Internally this is a free-list of indices threaded through the
 * unused slots themselves — zero memory overhead beyond the slabs.
 */
#ifndef PICOWEB_USERSPACE_CRYPTO_POOL_H
#define PICOWEB_USERSPACE_CRYPTO_POOL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t* slabs;              /* slot_size * slot_count bytes */
    uint32_t slot_size;          /* in bytes; >= sizeof(uint32_t) */
    uint32_t slot_count;         /* total slots */
    uint32_t free_head;          /* index of the next free slot (or slot_count if empty) */
    uint32_t in_use;             /* current number of rented slots */
    uint32_t high_water;         /* peak `in_use` since init */
    uint64_t exhaustion_count;   /* number of rent calls that returned NULL */
    uint64_t total_rents;        /* lifetime successful rents */
} buffer_pool_t;

/* Initialise a pool over caller-provided storage. `storage` must be
 * at least `slot_size * slot_count` bytes and aligned to at least
 * 8 bytes. `slot_size` must be >= 4. Returns 0 on success, -1 on
 * argument error. The pool DOES NOT free `storage`. */
int  pool_init(buffer_pool_t* p, void* storage,
               uint32_t slot_size, uint32_t slot_count);

/* Rent a single slot. Returns NULL on exhaustion (and bumps the
 * exhaustion counter). The returned pointer is `slot_size` bytes
 * and is suitably aligned for any standard layout. */
void* pool_rent(buffer_pool_t* p);

/* Release a slot previously returned by pool_rent. Passing a pointer
 * not from this pool is undefined behaviour (debug builds may
 * assert). The slot's contents are NOT zeroed — the caller is
 * responsible for wiping secrets via secure_zero before release. */
void  pool_release(buffer_pool_t* p, void* slot);

/* Compute storage size required for a given slot/count config.
 * Useful for sizing arena allocations at startup. */
static inline size_t pool_storage_bytes(uint32_t slot_size, uint32_t slot_count) {
    return (size_t)slot_size * (size_t)slot_count;
}

#endif
