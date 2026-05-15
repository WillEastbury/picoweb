/*
 * QUIC v1 flow control (RFC 9000 §4) — phase 4c.
 */
#include "flow.h"
#include <string.h>

void quic_flow_init(quic_flow_t* f, uint64_t initial_max)
{
    memset(f, 0, sizeof(*f));
    f->max = initial_max;
}

uint64_t quic_flow_consume(quic_flow_t* f, uint64_t bytes)
{
    uint64_t avail = (f->consumed >= f->max) ? 0 : (f->max - f->consumed);
    uint64_t take  = bytes < avail ? bytes : avail;
    f->consumed   += take;
    return take;
}

uint64_t quic_flow_available(const quic_flow_t* f)
{
    return (f->consumed >= f->max) ? 0 : (f->max - f->consumed);
}

void quic_flow_set_max(quic_flow_t* f, uint64_t new_max)
{
    if (new_max > f->max) f->max = new_max;
}

int quic_flow_should_update(const quic_flow_t* f, uint64_t initial_window)
{
    /* Push forward when remaining credit drops below half the original
     * window. Avoids per-byte MAX_DATA churn while still keeping the
     * sender's pipe full. */
    uint64_t half = initial_window / 2;
    uint64_t remaining = quic_flow_available(f);
    return remaining <= half;
}
