#include "tls_bridge.h"

#include <string.h>

void tls_bridge_init(tls_bridge_t* b, const jumptable_t* jt) {
    memset(b, 0, sizeof(*b));
    b->jt = jt;
}

int tls_bridge_parse_request(tls_bridge_t* b, const uint8_t* plain, size_t n) {
    if (!b || !plain) return -1;
    b->parse_status = http_parse((char*)plain, n, &b->req);
    if (b->parse_status == HTTP_OK) return 1;
    if (b->parse_status == HTTP_NEED_MORE) return 0;
    return -1;
}
