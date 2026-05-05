/*
 * Engine pool — fixed-size pool of `pw_tls_engine_t` slots.
 *
 * Built on `buffer_pool_t`. Strictly zero-allocation after init:
 * the caller hands us a pre-sized storage slab (typically static
 * .bss or arena bytes), we hand back zeroed engines on acquire and
 * scrub on release.
 *
 * Usage:
 *
 *   static uint8_t engines_storage[PW_TLS_ENGINE_POOL_BYTES(N_ENGINES)];
 *   pw_tls_engine_pool_t pool;
 *   pw_tls_engine_pool_init(&pool, engines_storage, N_ENGINES);
 *
 *   // hot path:
 *   pw_tls_engine_t* e = pw_tls_engine_pool_acquire(&pool);
 *   if (!e) { ... pool exhausted ... }
 *   ...
 *   pw_tls_engine_pool_release(&pool, e);
 *
 * `acquire` returns an engine in the same state as
 * `pw_tls_engine_init` — zeroed, ready to be configured with
 * `pw_tls_engine_configure_server` (or `install_app_keys` for the
 * spike path). `release` performs `secure_zero` over the entire
 * engine before threading it back onto the free list, so no key
 * material can leak into the next renter.
 */
#ifndef PICOWEB_USERSPACE_TLS_ENGINE_POOL_H
#define PICOWEB_USERSPACE_TLS_ENGINE_POOL_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/pool.h"
#include "engine.h"

/* Storage bytes required to back N engines. Use to size a static or
 * arena slab at startup. */
#define PW_TLS_ENGINE_POOL_BYTES(N)  ((size_t)sizeof(pw_tls_engine_t) * (size_t)(N))

typedef struct {
    buffer_pool_t base;          /* underlying slab pool */
} pw_tls_engine_pool_t;

/* Initialise an engine pool over caller-provided storage of at least
 * PW_TLS_ENGINE_POOL_BYTES(slot_count) bytes. `storage` must be aligned
 * for `pw_tls_engine_t` (8-byte alignment is sufficient on all our
 * targets — the engine is plain bytes + uint64 counters). Returns 0
 * on success, -1 on bad args. */
int pw_tls_engine_pool_init(pw_tls_engine_pool_t* p,
                            void* storage,
                            uint32_t slot_count);

/* Acquire a fresh engine from the pool. The engine is returned in
 * the same state as `pw_tls_engine_init` (all zeros). Returns NULL
 * if the pool is exhausted (and bumps `base.exhaustion_count`).
 *
 * After acquire, configure the engine for production use via
 * `pw_tls_engine_configure_server` (real handshake) or
 * `pw_tls_engine_install_app_keys` (spike fast-path). */
pw_tls_engine_t* pw_tls_engine_pool_acquire(pw_tls_engine_pool_t* p);

/* Return an engine to the pool. The entire engine is `secure_zero`d
 * before the slot is threaded back onto the free list — any key
 * material, transcript, or buffered plaintext is wiped. Passing a
 * pointer not previously returned by `acquire` on this pool is
 * undefined behaviour. NULL is a no-op. */
void pw_tls_engine_pool_release(pw_tls_engine_pool_t* p,
                                pw_tls_engine_t* eng);

/* ---------- introspection (operator-friendly counters) ---------- */

static inline uint32_t pw_tls_engine_pool_in_use(const pw_tls_engine_pool_t* p) {
    return p->base.in_use;
}
static inline uint32_t pw_tls_engine_pool_high_water(const pw_tls_engine_pool_t* p) {
    return p->base.high_water;
}
static inline uint64_t pw_tls_engine_pool_exhaustion(const pw_tls_engine_pool_t* p) {
    return p->base.exhaustion_count;
}
static inline uint64_t pw_tls_engine_pool_rents(const pw_tls_engine_pool_t* p) {
    return p->base.total_rents;
}
static inline uint32_t pw_tls_engine_pool_capacity(const pw_tls_engine_pool_t* p) {
    return p->base.slot_count;
}

#endif
