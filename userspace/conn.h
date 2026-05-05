/*
 * Per-connection run-to-completion runtime.
 *
 * One `pw_conn_t` is the in-memory state for a single TLS connection.
 * The webserver is decoupled from the stack via `pw_response_fn`
 * — given a request byte slice, it fills in a `pw_iov_t[]` of
 * response fragments pointing into the immutable static arena. The
 * runtime takes care of the TLS open / HTTP framing / TLS seal cycle
 * around it.
 *
 * One call (`pw_conn_rx`) drives the whole pipeline:
 *
 *   in bytes  -> TLS record reassembly
 *             -> AEAD open (in-place over reassembled record)
 *             -> HTTP slice  (caller provides response_fn)
 *             -> AEAD seal_iov (over response fragments)
 *             -> wire bytes ready for TCP segmentation
 *
 * No allocation. All state inline. The buffers are sized for one TLS
 * record in flight per direction; a real implementation would rent
 * these from a per-worker pool and release on idle, but for the spike
 * the per-conn budget is fixed.
 */
#ifndef PICOWEB_USERSPACE_CONN_H
#define PICOWEB_USERSPACE_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "iov.h"
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
    /* Per-direction TLS record state (caller initialises before
     * first use; the runtime advances seq numbers on each record). */
    tls_record_dir_t rx;
    tls_record_dir_t tx;

    /* RX reassembly buffer: accumulates wire bytes until at least a
     * full record is available. Sized for one record. */
    uint8_t  rx_buf[PW_CONN_MAX_RECORD];
    size_t   rx_len;

    /* Plaintext working buffer: AEAD-open writes here. */
    uint8_t  pt_buf[TLS13_MAX_PLAINTEXT];

    /* Diagnostics. */
    uint64_t records_in;
    uint64_t records_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
} pw_conn_t;

void pw_conn_init(pw_conn_t* c,
                  const tls_record_dir_t* rx_dir,
                  const tls_record_dir_t* tx_dir);

/* Feed wire bytes (post-TCP-reassembly) into the connection. The
 * runtime appends them to the rx buffer; once a full TLS record is
 * present it is decrypted, the inner plaintext is treated as an HTTP
 * request, the response_fn produces a response iov chain, and the
 * runtime seals one outbound record into `out`.
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
