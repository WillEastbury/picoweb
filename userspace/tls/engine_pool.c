/*
 * Engine pool — implementation. See engine_pool.h.
 *
 * The underlying buffer_pool stores its free-list pointer in the
 * first 4 bytes of each slot. Because we ALWAYS run
 * `pw_tls_engine_init` on acquire (which secure_zeroes the whole
 * engine), and ALWAYS secure_zero on release (overwriting the
 * just-installed free-list pointer is fine — we re-thread on
 * release AFTER the wipe), there is no risk of those 4 bytes
 * being read by user code as engine state.
 */

#include "engine_pool.h"

#include <string.h>

#include "../crypto/util.h"

int pw_tls_engine_pool_init(pw_tls_engine_pool_t* p,
                            void* storage,
                            uint32_t slot_count) {
    if (!p) return -1;
    /* slot_size is sizeof(pw_tls_engine_t) — comfortably > 4 bytes. */
    return pool_init(&p->base, storage,
                     (uint32_t)sizeof(pw_tls_engine_t), slot_count);
}

pw_tls_engine_t* pw_tls_engine_pool_acquire(pw_tls_engine_pool_t* p) {
    if (!p) return NULL;
    void* slot = pool_rent(&p->base);
    if (!slot) return NULL;
    pw_tls_engine_t* eng = (pw_tls_engine_t*)slot;
    /* The slot's first 4 bytes still hold the old free-list pointer
     * at this moment — pw_tls_engine_init's secure_zero of the whole
     * engine erases that and gives the caller a clean engine. */
    pw_tls_engine_init(eng);
    return eng;
}

void pw_tls_engine_pool_release(pw_tls_engine_pool_t* p,
                                pw_tls_engine_t* eng) {
    if (!p || !eng) return;
    /* Wipe ALL engine state — keys, transcript, plaintext buffers,
     * everything — before returning to the free list. pool_release
     * will then overwrite the first 4 bytes with the next-free
     * index, which is fine because the slot is no longer usable as
     * an engine until the next acquire calls pw_tls_engine_init. */
    secure_zero(eng, sizeof(*eng));
    pool_release(&p->base, eng);
}
