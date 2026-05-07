#ifndef PICOWEB_TLS_BRIDGE_H
#define PICOWEB_TLS_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#include "http.h"
#include "jumptable.h"

/* Minimal bridge scaffold between the userspace TLS stack and the
 * existing HTTP/jumptable pipeline.
 *
 * This is intentionally tiny in this commit: it gives us stable types
 * and call points while the real TCP/TLS I/O loop lands in follow-up
 * commits. */
typedef struct {
    const jumptable_t* jt;
    http_request_t     req;
    http_result_t      parse_status;
} tls_bridge_t;

void tls_bridge_init(tls_bridge_t* b, const jumptable_t* jt);

/* Parse one plaintext HTTP request in-place.
 * Returns:
 *   1  parsed successfully
 *   0  incomplete request (need more bytes)
 *  -1  parse error */
int tls_bridge_parse_request(tls_bridge_t* b, const uint8_t* plain, size_t n);

#endif
