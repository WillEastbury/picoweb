/*
 * Pre-jump table for L4 services. Built once at startup, never mutated.
 * See dispatch.h for the lifecycle contract.
 */

#include "dispatch.h"

#include <string.h>

void pw_dispatch_init(pw_dispatch_t* d) {
    if (!d) return;
    memset(d, 0, sizeof(*d));
}

int pw_dispatch_register(pw_dispatch_t* d, const pw_service_t* svc) {
    if (!d || !svc)            return -1;
    if (svc->port == 0)        return -1;
    if (svc->on_data == NULL)  return -1;
    if (svc->proto != PW_PROTO_TCP && svc->proto != PW_PROTO_UDP) return -1;
    if (d->n >= PW_DISPATCH_MAX) return -1;

    /* Reject duplicates (same proto + port). */
    for (unsigned i = 0; i < d->n; i++) {
        if (d->entries[i].proto == svc->proto &&
            d->entries[i].port  == svc->port) {
            return -1;
        }
    }

    d->entries[d->n] = *svc;
    d->n++;
    return 0;
}

const pw_service_t* pw_dispatch_lookup(const pw_dispatch_t* d,
                                       pw_proto_t proto, uint16_t port) {
    if (!d) return NULL;
    /* Linear scan. N <= 16, fits in one cache line, branch predictor
     * wins for small N. See dispatch.h for the rationale. */
    for (unsigned i = 0; i < d->n; i++) {
        const pw_service_t* e = &d->entries[i];
        if (e->port == port && e->proto == proto) return e;
    }
    return NULL;
}
