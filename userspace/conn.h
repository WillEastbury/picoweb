/*
 * Per-connection run-to-completion runtime.
 *
 * `pw_conn_t` is a thin convenience wrapper around `pw_tls_engine_t`
 * for callers that want the legacy "give me bytes, get sealed bytes
 * back" run-to-completion shape rather than the engine's port-based
 * state machine. The webserver is decoupled from the stack via
 * `pw_response_fn` — given a request byte slice, it fills in a
 * `pw_iov_t[]` of response fragments pointing into the immutable
 * static arena. The runtime takes care of the TLS open / HTTP framing
 * / TLS seal cycle around it.
 *
 * One call (`pw_conn_rx`) drives the whole pipeline:
 *
 *   in bytes  -> pw_tls_engine RX
 *             -> pw_tls_step  (AEAD open into APP_IN)
 *             -> HTTP slice   (caller provides response_fn)
 *             -> pw_tls_app_seal_iov  (zero-copy seal of iov chain)
 *             -> wire bytes ready for TCP segmentation
 *
 * No allocation. All state inline (engine is ~64 KiB; conn adds only
 * counters). The buffers are sized for one TLS record in flight per
 * direction (the engine owns them); a real implementation would rent
 * the engine from a per-worker pool.
 */
#ifndef PICOWEB_USERSPACE_CONN_H
#define PICOWEB_USERSPACE_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "iov.h"
#include "tls/engine.h"
#include "tls/record.h"

#define PW_CONN_MAX_REQUEST  TLS13_MAX_PLAINTEXT
#define PW_CONN_MAX_RECORD   (TLS13_RECORD_HEADER_LEN + TLS13_MAX_CIPHERTEXT)

typedef struct {
    pw_iov_t parts[PW_IOV_MAX_FRAGS];
    unsigned n;
    size_t   total_len;       /* sum of parts[].len; precomputed */
} pw_response_t;

/* Webserver-as-module callback. The runtime invokes this once a
 * complete HTTP request has been sliced out of a decrypted TLS
 * record. The callee fills in `out` with descriptors pointing at
 * long-lived storage (typically `arena_alloc_immutable()` bytes).
 *
 * Aliasing contract:
 *   - The `request` pointer is valid ONLY for the duration of this
 *     call. The callee must not retain it.
 *   - Response fragments (`out->parts[i].base`) MUST NOT alias the
 *     request bytes nor any engine buffer. They must point at
 *     storage with at least pw_conn lifetime (typically the static
 *     arena).
 *
 * Returns 0 on success, -1 on internal error (the runtime will then
 * close the connection with an internal error alert). */
typedef int (*pw_response_fn)(const uint8_t* request, size_t request_len,
                              pw_response_t* out, void* user);

typedef enum {
    PW_CONN_OK            = 0,
    PW_CONN_NEED_MORE     = 1,    /* not enough RX bytes for a record */
    PW_CONN_PROTOCOL_ERR  = -1,
    PW_CONN_AUTH_FAIL     = -2,
    PW_CONN_RESPONSE_FAIL = -3,
    PW_CONN_OUT_OVERFLOW  = -4,
} pw_conn_status_t;

typedef struct {
    /* The engine owns rx_buf / tx_buf / app_in_buf / app_out_buf and
     * the per-direction record state. We embed it directly so the
     * conn lifetime is the engine lifetime. */
    pw_tls_engine_t engine;

    /* Diagnostics. Mirror the legacy counters so callers' metrics
     * keep working without reaching into the engine. */
    uint64_t records_in;
    uint64_t records_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
} pw_conn_t;

/* Initialise a pw_conn over pre-derived application-traffic record
 * directions. The conn skips the handshake — it goes straight to
 * APP state via the engine's spike-mode shortcut. Used by tests
 * and by services that want a simpler interface than the engine
 * port API. */
void pw_conn_init(pw_conn_t* c,
                  const tls_record_dir_t* rx_dir,
                  const tls_record_dir_t* tx_dir);

/* Feed wire bytes (post-TCP-reassembly) into the connection. The
 * runtime appends them to the engine's RX; once a full TLS record
 * is present it is decrypted, the inner plaintext is treated as an
 * HTTP request, the response_fn produces a response iov chain, and
 * the runtime seals one outbound record into `out`.
 *
 * Returns:
 *   PW_CONN_OK         — wrote `*out_len` bytes of sealed wire data
 *   PW_CONN_NEED_MORE  — buffered `in` but not enough for a record yet
 *   PW_CONN_*          — protocol / auth / response / overflow error
 *
 * Pre-condition: `out_cap >= PW_CONN_MAX_RECORD` for any non-trivial
 * response. The runtime emits ONE response record per call (HTTP/1.1
 * single-shot). */
pw_conn_status_t pw_conn_rx(pw_conn_t* c,
                            const uint8_t* in, size_t in_len,
                            pw_response_fn response_fn, void* response_user,
                            uint8_t* out, size_t out_cap, size_t* out_len);

#endif
