/*
 * Server-side TLS 1.3 session ticket store (RFC 8446 §4.6.1).
 *
 * Fixed-size, zero-allocation, single-thread. Each ticket records:
 *   - ticket_id: opaque bytes the client returns in pre_shared_key
 *   - psk[32]:   per-ticket PSK = HKDF-Expand-Label(RMS,"resumption",
 *                                                   nonce, 32)
 *   - age_add:   client adds this (mod 2^32) to its observed age
 *   - lifetime_s: seconds the ticket remains usable
 *   - issued_at_ms: monotonic millisecond timestamp at issuance
 *   - max_early_data: per-ticket 0-RTT cap (0 = no early data)
 *   - used:      single-shot anti-replay defense for 0-RTT (RFC 8446
 *                §8). A used ticket is still valid for the 1-RTT
 *                handshake but rejects 0-RTT.
 *
 * No allocations. Fixed slot count. Eviction policy is oldest-first
 * (LRU by issuance time).
 *
 * Caller is responsible for monotonic time and for never sharing
 * one store between threads without external synchronisation.
 */
#ifndef PICOWEB_USERSPACE_TLS_TICKET_STORE_H
#define PICOWEB_USERSPACE_TLS_TICKET_STORE_H

#include <stddef.h>
#include <stdint.h>

#define PW_TLS_TICKET_ID_MAX   64u
#define PW_TLS_TICKET_SLOTS    16u

typedef struct {
    int      valid;
    uint8_t  ticket_id[PW_TLS_TICKET_ID_MAX];
    uint8_t  id_len;
    uint8_t  psk[32];
    uint32_t age_add;
    uint32_t lifetime_s;
    uint64_t issued_at_ms;
    uint32_t max_early_data;
    int      used;
} pw_tls_ticket_t;

typedef struct pw_tls_ticket_store {
    pw_tls_ticket_t slots[PW_TLS_TICKET_SLOTS];
} pw_tls_ticket_store_t;

void pw_tls_ticket_store_init(pw_tls_ticket_store_t* s);

/* Insert a new ticket. Evicts the oldest valid slot if full. Returns
 * 0 on success, -1 on bad args (id_len out of range). The store
 * COPIES psk + ticket_id. */
int  pw_tls_ticket_store_insert(pw_tls_ticket_store_t* s,
                                const uint8_t* ticket_id, size_t id_len,
                                const uint8_t  psk[32],
                                uint32_t age_add,
                                uint32_t lifetime_s,
                                uint64_t issued_at_ms,
                                uint32_t max_early_data);

/* Lookup by ticket_id. Returns pointer to the slot (do NOT mutate
 * .ticket_id / .id_len / .psk through it) or NULL if not found or
 * expired (issued_at_ms + lifetime_s*1000 < now_ms). */
pw_tls_ticket_t* pw_tls_ticket_store_lookup(pw_tls_ticket_store_t* s,
                                            const uint8_t* ticket_id, size_t id_len,
                                            uint64_t now_ms);

/* Mark a ticket "used" for 0-RTT. After this call the same ticket
 * still permits 1-RTT resumption but pw_tls_ticket_can_early_data()
 * returns 0. Returns 0 on success, -1 if ticket was already used. */
int pw_tls_ticket_consume_for_0rtt(pw_tls_ticket_t* t);

/* Convenience: returns 1 if 0-RTT is allowed (max_early_data > 0
 * and !used), else 0. */
int pw_tls_ticket_can_early_data(const pw_tls_ticket_t* t);

/* Wipe + invalidate a single slot. */
void pw_tls_ticket_invalidate(pw_tls_ticket_t* t);

#endif
