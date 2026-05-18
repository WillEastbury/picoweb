#ifndef PICOWEB_TLS_CERTS_H
#define PICOWEB_TLS_CERTS_H

#include <stddef.h>

/* Resolve where the TLS cert + key files live.
 *
 * Resolution order (first match wins):
 *   1. Explicit CLI flags (cli_cert + cli_key, both non-NULL).
 *      If only one of the two is provided, this is a hard error.
 *   2. /certs/tls.crt + /certs/tls.key  (k8s cert-manager Secret
 *      mounted as a directory — the canonical layout for a
 *      kubernetes.io/tls Secret.)
 *   3. ./certs/tls.crt + ./certs/tls.key  (local-dev convention).
 *
 * On success, copies the resolved absolute-or-relative paths into
 * the caller's cert_out / key_out buffers (each at least cap bytes)
 * and returns 0.
 *
 * On failure, returns -1. If `errstream` is non-NULL, writes a
 * single-line diagnostic explaining what was tried.
 *
 * `cap` should be >= PATH_MAX (4096 is fine).
 *
 * The function only checks PRESENCE (access(F_OK)) and READABILITY
 * (access(R_OK)). Format validation is the caller's job (call
 * pem_decode_chain / pem_decode after this).
 */
int picoweb_tls_locate_certs(const char* cli_cert, const char* cli_key,
                             char* cert_out, char* key_out, size_t cap,
                             void* errstream /* FILE*, NULL = stderr */);

#endif
