/*
 * QUIC v1 special packets + idle timer (RFC 9000 §10, §17.2.1) — phase 4d.
 *
 *   Stateless reset packet (§10.3): looks like a short-header packet,
 *   ends with the 16-byte stateless_reset_token. Used when the server
 *   loses connection state but still receives traffic on a CID.
 *
 *   Version negotiation packet (§17.2.1): long-header form with
 *   version=0; lists supported versions. Sent in response to an
 *   unknown long-header version.
 *
 *   Idle timeout (§10.1): pure helper, returns 1 once the channel
 *   has been silent for at least the negotiated timeout.
 */
#ifndef PICOWEB_USERSPACE_QUIC_SPECIAL_H
#define PICOWEB_USERSPACE_QUIC_SPECIAL_H

#include <stdint.h>
#include <stddef.h>

/* Minimum stateless-reset packet length (RFC 9000 §10.3): 22 bytes
 * total, of which the last 16 are the token. */
#define QUIC_STATELESS_RESET_MIN     22
#define QUIC_STATELESS_RESET_TOKEN_LEN 16

/* Build a stateless reset packet:
 *   out[0]   = 0x40 | (random[0] & 0x3f)   (short-header form, fixed bit)
 *   out[1..n-16] = random_pad             (caller-supplied randomness)
 *   out[n-16..n] = token
 *
 * Returns bytes written on success, 0 if cap < QUIC_STATELESS_RESET_MIN
 * or rand_len < (cap - 16).
 *
 * `rand` must be at least (cap - 16) bytes of caller-supplied entropy
 * (we don't pull from the kernel here so this stays unit-testable). */
size_t quic_stateless_reset_build(uint8_t* out, size_t cap,
                                  const uint8_t* rand_buf, size_t rand_len,
                                  const uint8_t token[QUIC_STATELESS_RESET_TOKEN_LEN]);

/* Detect whether `pkt` could be a stateless reset for `token`. RFC 9000
 * §10.3.1: any packet whose final 16 bytes equal the expected token
 * MUST be treated as a stateless reset. */
int quic_stateless_reset_match(const uint8_t* pkt, size_t pkt_len,
                               const uint8_t token[QUIC_STATELESS_RESET_TOKEN_LEN]);

/* Build a version-negotiation packet (RFC 9000 §17.2.1):
 *   byte0    = 1xxx xxxx (form bit set; remaining bits unspecified)
 *   version  = 0x00000000
 *   dcid_len, dcid    (echo client SCID)
 *   scid_len, scid    (echo client DCID)
 *   versions[]        (each 4-byte big-endian)
 *
 * `client_dcid`/`client_scid` come straight from the unknown-version
 * packet that triggered VN. The server echoes them swapped.
 *
 * Returns bytes written, or 0 on capacity error. */
size_t quic_version_negotiation_build(uint8_t* out, size_t cap,
                                      uint8_t byte0_low7,
                                      const uint8_t* client_dcid, size_t client_dcid_len,
                                      const uint8_t* client_scid, size_t client_scid_len,
                                      const uint32_t* versions, size_t n_versions);

/* Idle timer (RFC 9000 §10.1). Returns 1 iff
 *   now_us >= last_recv_us + idle_timeout_us
 * with idle_timeout_us == 0 meaning "no timeout". */
int quic_idle_expired(uint64_t last_recv_us,
                      uint64_t idle_timeout_us,
                      uint64_t now_us);

#endif
