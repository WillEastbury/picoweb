#include "ticket_store.h"

#include <string.h>

#include "../crypto/util.h"

void pw_tls_ticket_store_init(pw_tls_ticket_store_t* s) {
    if (!s) return;
    secure_zero(s, sizeof(*s));
}

void pw_tls_ticket_invalidate(pw_tls_ticket_t* t) {
    if (!t) return;
    secure_zero(t, sizeof(*t));
}

static int ticket_eq(const pw_tls_ticket_t* t,
                     const uint8_t* id, size_t id_len) {
    if (!t->valid) return 0;
    if (t->id_len != id_len) return 0;
    /* Constant-time compare for the common id_len. */
    uint8_t acc = 0;
    for (size_t i = 0; i < id_len; i++) acc |= (uint8_t)(t->ticket_id[i] ^ id[i]);
    return acc == 0;
}

int pw_tls_ticket_store_insert(pw_tls_ticket_store_t* s,
                               const uint8_t* ticket_id, size_t id_len,
                               const uint8_t  psk[32],
                               uint32_t age_add,
                               uint32_t lifetime_s,
                               uint64_t issued_at_ms,
                               uint32_t max_early_data) {
    if (!s || !ticket_id || !psk)            return -1;
    if (id_len == 0 || id_len > PW_TLS_TICKET_ID_MAX) return -1;

    /* First pass: if a ticket with the same id exists, replace it
     * (caller can rotate). Otherwise find an empty slot. Otherwise
     * evict the oldest valid one. */
    pw_tls_ticket_t* victim = NULL;
    uint64_t         victim_age = (uint64_t)-1;
    for (unsigned i = 0; i < PW_TLS_TICKET_SLOTS; i++) {
        pw_tls_ticket_t* t = &s->slots[i];
        if (ticket_eq(t, ticket_id, id_len)) { victim = t; break; }
        if (!t->valid) { victim = t; break; }
        if (t->issued_at_ms < victim_age) {
            victim     = t;
            victim_age = t->issued_at_ms;
        }
    }
    if (!victim) return -1;   /* unreachable: PW_TLS_TICKET_SLOTS >= 1 */

    secure_zero(victim, sizeof(*victim));
    memcpy(victim->ticket_id, ticket_id, id_len);
    victim->id_len         = (uint8_t)id_len;
    memcpy(victim->psk, psk, 32);
    victim->age_add        = age_add;
    victim->lifetime_s     = lifetime_s;
    victim->issued_at_ms   = issued_at_ms;
    victim->max_early_data = max_early_data;
    victim->used           = 0;
    victim->valid          = 1;
    return 0;
}

pw_tls_ticket_t* pw_tls_ticket_store_lookup(pw_tls_ticket_store_t* s,
                                            const uint8_t* ticket_id, size_t id_len,
                                            uint64_t now_ms) {
    if (!s || !ticket_id || id_len == 0 || id_len > PW_TLS_TICKET_ID_MAX) return NULL;
    for (unsigned i = 0; i < PW_TLS_TICKET_SLOTS; i++) {
        pw_tls_ticket_t* t = &s->slots[i];
        if (!ticket_eq(t, ticket_id, id_len)) continue;
        /* Expiry check. lifetime_s == 0 means immediately expired. */
        uint64_t exp_ms = t->issued_at_ms + (uint64_t)t->lifetime_s * 1000ull;
        if (exp_ms < now_ms) {
            pw_tls_ticket_invalidate(t);
            return NULL;
        }
        return t;
    }
    return NULL;
}

int pw_tls_ticket_consume_for_0rtt(pw_tls_ticket_t* t) {
    if (!t || !t->valid)        return -1;
    if (t->used)                return -1;
    t->used = 1;
    return 0;
}

int pw_tls_ticket_can_early_data(const pw_tls_ticket_t* t) {
    if (!t || !t->valid) return 0;
    if (t->used)         return 0;
    return t->max_early_data > 0 ? 1 : 0;
}
