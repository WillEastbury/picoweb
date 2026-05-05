/*
 * Minimal TCP state machine — passive open, happy path only.
 *
 * Two mux modes:
 *   - Legacy single-port:   tcp_listen + tcp_input(on_data,...)
 *   - Multi-service:        tcp_attach_dispatch + tcp_input(NULL,...)
 *
 * The dispatch path is the new model and is what new code should use.
 * Lifecycle contract for services lives in dispatch.h.
 *
 * NOT a production stack. See tcp.h for the explicit exclusions.
 */

#include "tcp.h"

#include <string.h>

static void rtx_on_ack(tcp_conn_t* c, uint32_t ack_no, uint64_t now_ms);
static void cc_on_new_ack(tcp_conn_t* c, uint32_t bytes_acked);
static void cc_on_dupack(tcp_conn_t* c, tcp_emit_fn emit, void* emit_user);
static void cc_on_rto(tcp_conn_t* c);

/* RFC 6528 §3 ISN derivation:
 *   ISN = M + F(local_ip, local_port, remote_ip, remote_port, secret)
 * where M is a monotonic clock and F is a keyed PRF over the 4-tuple.
 * We use a SipHash-style mix (rotate + xor + multiply) keyed on the
 * per-stack iss_secret. If the owner never installed a secret, the
 * secret is all-zero but the 4-tuple still produces 2^32 distinct ISN
 * baselines — orders of magnitude better than the legacy fixed value
 * but NOT a substitute for a real RNG-seeded secret. Owners who care
 * about RFC 9293 §3.4.1 blind-injection resistance MUST call
 * tcp_stack_set_iss_secret() at startup with 16 bytes of CSPRNG. */
static uint32_t iss_derive(const tcp_stack_t* s,
                           uint32_t local_ip,  uint16_t local_port,
                           uint32_t remote_ip, uint16_t remote_port,
                           uint64_t now_ms) {
    uint64_t k0 = 0, k1 = 0;
    for (int i = 0; i < 8; i++) {
        k0 |= (uint64_t)s->iss_secret[i]      << (i * 8);
        k1 |= (uint64_t)s->iss_secret[i + 8]  << (i * 8);
    }
    uint64_t v = ((uint64_t)local_ip << 32) ^ remote_ip;
    v ^= ((uint64_t)local_port << 16) ^ remote_port;
    v ^= k0;
    /* Two rounds of mix (loosely SipHash-like). */
    v = (v ^ (v >> 33)) * 0xff51afd7ed558ccdull;
    v ^= k1;
    v = (v ^ (v >> 33)) * 0xc4ceb9fe1a85ec53ull;
    v ^= (v >> 33);
    /* RFC 6528 advances the baseline at the rate of a fast clock.
     * Mix in a quarter of now_ms so retried 4-tuples within a
     * couple of seconds still pick up a different ISN. */
    return (uint32_t)v + (uint32_t)(now_ms << 18);
}

void tcp_stack_set_iss_secret(tcp_stack_t* s, const uint8_t* secret, size_t len) {
    if (!s) return;
    size_t n = len < sizeof(s->iss_secret) ? len : sizeof(s->iss_secret);
    if (n) memcpy(s->iss_secret, secret, n);
    if (n < sizeof(s->iss_secret)) memset(s->iss_secret + n, 0, sizeof(s->iss_secret) - n);
}

static tcp_conn_t* find_conn(tcp_stack_t* s, const tcp_seg_t* seg) {
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        tcp_conn_t* c = &s->conns[i];
        if (c->state == TCP_CLOSED) continue;
        if (c->state == TCP_LISTEN) continue;            /* skip the LISTEN PCB */
        if (c->local_port  == seg->dst_port &&
            c->remote_port == seg->src_port &&
            c->local_ip    == seg->dst_ip &&
            c->remote_ip   == seg->src_ip) return c;
    }
    return NULL;
}

static tcp_conn_t* alloc_conn(tcp_stack_t* s) {
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        if (s->conns[i].state == TCP_CLOSED) return &s->conns[i];
    }
    return NULL;
}

uint16_t tcp_advertised_wnd(const tcp_conn_t* c) {
    if (!c) return 0;
    /* Legacy default: cap == 0 means flow-control disabled. */
    if (c->rcv_buf_cap == 0) return 65535;
    if (c->rcv_buf_used >= c->rcv_buf_cap) return 0;
    uint32_t free_bytes = c->rcv_buf_cap - c->rcv_buf_used;
    return (free_bytes > 65535u) ? 65535u : (uint16_t)free_bytes;
}

void tcp_set_rcv_buf_cap(tcp_conn_t* c, uint32_t cap) {
    if (!c) return;
    c->rcv_buf_cap  = cap;
    c->rcv_buf_used = 0;
    c->rcv_wnd      = tcp_advertised_wnd(c);
}

void tcp_rcv_consumed(tcp_conn_t* c, uint32_t n,
                      tcp_emit_fn emit, void* emit_user) {
    if (!c || n == 0) return;
    uint16_t old_wnd = c->rcv_wnd;
    if (n >= c->rcv_buf_used) c->rcv_buf_used = 0;
    else                      c->rcv_buf_used -= n;
    uint16_t new_wnd = tcp_advertised_wnd(c);
    c->rcv_wnd = new_wnd;
    /* Window opened from 0 -> >0: emit a window-update ACK so the
     * peer (who has been sending persist probes) starts sending data
     * again. RFC 9293 §3.8.6.2. */
    if (old_wnd == 0 && new_wnd > 0 && c->state == TCP_ESTABLISHED && emit) {
        tcp_seg_t s = {0};
        s.src_ip   = c->local_ip;
        s.dst_ip   = c->remote_ip;
        s.src_port = c->local_port;
        s.dst_port = c->remote_port;
        s.seq      = c->snd_nxt;
        s.ack      = c->rcv_nxt;
        s.flags    = TCPF_ACK;
        s.window   = new_wnd;
        emit(&s, emit_user);
    }
}

static void emit_ctrl(tcp_conn_t* c, uint8_t flags,
                      tcp_emit_fn emit, void* user) {
    /* Always recompute the window at emit time so any application
     * activity since the last segment is reflected. */
    c->rcv_wnd = tcp_advertised_wnd(c);
    tcp_seg_t s = {0};
    s.src_ip   = c->local_ip;
    s.dst_ip   = c->remote_ip;
    s.src_port = c->local_port;
    s.dst_port = c->remote_port;
    s.seq      = c->snd_nxt;
    s.ack      = c->rcv_nxt;
    s.flags    = flags;
    s.window   = c->rcv_wnd;
    emit(&s, user);
}

static void emit_rst(const tcp_seg_t* in, tcp_emit_fn emit, void* user) {
    tcp_seg_t s = {0};
    s.src_ip   = in->dst_ip;
    s.dst_ip   = in->src_ip;
    s.src_port = in->dst_port;
    s.dst_port = in->src_port;
    if (in->flags & TCPF_ACK) {
        s.seq = in->ack;
        s.flags = TCPF_RST;
    } else {
        s.seq = 0;
        s.ack = in->seq + (in->flags & TCPF_SYN ? 1 : 0) + in->payload_len;
        s.flags = TCPF_RST | TCPF_ACK;
    }
    s.window = 0;
    emit(&s, user);
}

int tcp_listen(tcp_stack_t* s, uint32_t local_ip, uint16_t listen_port) {
    memset(s, 0, sizeof(*s));
    s->local_ip = local_ip;
    s->listen_port = listen_port;
    /* Slot 0 is the LISTEN PCB; the others are spare connections. */
    s->conns[0].state = TCP_LISTEN;
    s->conns[0].local_ip = local_ip;
    s->conns[0].local_port = listen_port;
    return 0;
}

int tcp_attach_dispatch(tcp_stack_t* s, uint32_t local_ip,
                        const pw_dispatch_t* d) {
    if (!s || !d) return -1;
    memset(s, 0, sizeof(*s));
    s->local_ip = local_ip;
    s->dispatch = d;
    /* No LISTEN PCB - any port that resolves via dispatch accepts. */
    return 0;
}

/* Decide whether to accept a SYN to `dst_port`. In dispatch mode,
 * we accept iff a service is registered for that port. In legacy
 * mode, we accept iff dst_port == listen_port. Returns the matched
 * service (NULL is allowed in legacy mode). */
static int port_accepts(tcp_stack_t* s, uint16_t dst_port,
                        const pw_service_t** svc_out) {
    *svc_out = NULL;
    if (s->dispatch) {
        const pw_service_t* svc =
            pw_dispatch_lookup(s->dispatch, PW_PROTO_TCP, dst_port);
        if (!svc) return 0;
        *svc_out = svc;
        return 1;
    }
    return dst_port == s->listen_port ? 1 : 0;
}

/* Fire the service's on_open hook (only after ESTABLISHED). On
 * service refusal (NULL return) the conn is reset. Returns 1 if the
 * connection should remain open, 0 if it has been torn down. */
static int fire_open(tcp_conn_t* c, tcp_emit_fn emit, void* emit_user) {
    if (!c->svc || c->opened) return 1;
    if (!c->svc->on_open) {
        /* Service has no per-conn state - mark opened so on_close
         * (if any) is also skipped. */
        c->opened = 1;
        return 1;
    }
    pw_conn_info_t info = {
        .remote_ip   = c->remote_ip,
        .remote_port = c->remote_port,
        .local_ip    = c->local_ip,
        .local_port  = c->local_port,
        .proto       = PW_PROTO_TCP,
    };
    void* st = c->svc->on_open(c->svc->svc_state, &info);
    if (!st) {
        /* Pool exhausted or service refused - RST. */
        emit_ctrl(c, TCPF_RST, emit, emit_user);
        c->state = TCP_CLOSED;
        return 0;
    }
    c->app_state = st;
    c->opened    = 1;
    return 1;
}

/* Fire the service's on_close hook EXACTLY ONCE, only if on_open
 * fired and returned non-NULL. Idempotent on repeat calls. */
static void fire_close(tcp_conn_t* c) {
    if (!c->svc || !c->opened) return;
    if (c->svc->on_close && c->app_state) {
        c->svc->on_close(c->app_state);
    }
    c->app_state = NULL;
    c->opened    = 0;
}

/* Drive a service's on_data and act on the returned status. Returns
 * 1 if the connection remains open, 0 if it has been torn down. */
static int drive_service_data(tcp_conn_t* c,
                              const uint8_t* data, size_t len,
                              tcp_emit_fn emit, void* emit_user) {
    pw_iov_t iov[PW_IOV_MAX_FRAGS];
    unsigned iov_n = 0;
    pw_disp_status_t st = c->svc->on_data(c->app_state, data, len,
                                          iov, PW_IOV_MAX_FRAGS, &iov_n);
    switch (st) {
    case PW_DISP_NO_OUTPUT:
        return 1;
    case PW_DISP_OUTPUT:
        if (iov_n) tcp_sendv(c, iov, iov_n, emit, emit_user);
        return 1;
    case PW_DISP_OUTPUT_AND_CLOSE:
        if (iov_n) tcp_sendv(c, iov, iov_n, emit, emit_user);
        emit_ctrl(c, TCPF_FIN | TCPF_ACK, emit, emit_user);
        c->snd_nxt++;                /* +1 for our FIN */
        c->state = TCP_LAST_ACK;
        return 1;
    case PW_DISP_RESET:
    case PW_DISP_ERROR:
    default:
        emit_ctrl(c, TCPF_RST, emit, emit_user);
        fire_close(c);
        c->state = TCP_CLOSED;
        return 0;
    }
}

void tcp_input(tcp_stack_t* s, const tcp_seg_t* seg,
               tcp_on_data_fn on_data, void* on_data_user,
               tcp_emit_fn emit, void* emit_user) {
    tcp_input_at(s, seg, 0, on_data, on_data_user, emit, emit_user);
}

void tcp_input_at(tcp_stack_t* s, const tcp_seg_t* seg,
                  uint64_t now_ms,
                  tcp_on_data_fn on_data, void* on_data_user,
                  tcp_emit_fn emit, void* emit_user) {
    /* Reject if not addressed to our local IP. */
    if (seg->dst_ip != s->local_ip) {
        emit_rst(seg, emit, emit_user);
        return;
    }

    /* Port accept check (dispatch lookup or single-port match). */
    const pw_service_t* svc = NULL;
    int port_ok = port_accepts(s, seg->dst_port, &svc);
    if (!port_ok) {
        emit_rst(seg, emit, emit_user);
        return;
    }

    tcp_conn_t* c = find_conn(s, seg);

    /* No matching PCB. If it's a SYN, allocate one and move to
     * SYN-RECEIVED; otherwise RST. */
    if (!c) {
        if (!(seg->flags & TCPF_SYN) || (seg->flags & TCPF_ACK)) {
            emit_rst(seg, emit, emit_user);
            return;
        }
        c = alloc_conn(s);
        if (!c) { emit_rst(seg, emit, emit_user); return; }
        c->state       = TCP_SYN_RECEIVED;
        c->local_ip    = seg->dst_ip;
        c->remote_ip   = seg->src_ip;
        c->local_port  = seg->dst_port;
        c->remote_port = seg->src_port;
        c->rcv_nxt     = seg->seq + 1;     /* +1 for SYN */
        c->snd_nxt     = iss_derive(s,
                                    seg->dst_ip, seg->dst_port,
                                    seg->src_ip, seg->src_port,
                                    now_ms);
        c->snd_una     = c->snd_nxt;
        c->rcv_wnd     = 65535;
        /* Congestion control init (RFC 5681 + RFC 6928 IW10). */
        c->cwnd         = TCP_INIT_CWND;
        c->ssthresh     = 0xffffffffu;     /* "infinity" until first loss */
        c->snd_wnd      = seg->window ? seg->window : 65535u;
        c->dupack_n     = 0;
        c->in_recovery  = 0;
        c->recovery_seq = 0;
        c->svc         = svc;              /* may be NULL in legacy mode */
        c->app_state   = NULL;
        c->opened      = 0;
        emit_ctrl(c, TCPF_SYN | TCPF_ACK, emit, emit_user);
        c->snd_nxt++;                      /* +1 for our SYN */
        return;
    }

    /* RST tears down — but only if the ACK field falls in the
     * current send window (RFC 9293 §3.10.7.4 / §3.5.2). Without
     * this check, an off-path attacker can blind-inject RST by
     * spraying the rcv_nxt seq space; requiring a valid ACK field
     * raises the work factor by ~2^32. SYN-RECEIVED tolerates RST
     * with no ACK because the peer may abort before our SYN-ACK
     * lands; in that state we just check seq is in window. */
    if (seg->flags & TCPF_RST) {
        int rst_ok = 0;
        if (c->state == TCP_SYN_RECEIVED) {
            rst_ok = (seg->seq == c->rcv_nxt);
        } else if (seg->flags & TCPF_ACK) {
            int32_t lo = (int32_t)(seg->ack - c->snd_una);
            int32_t hi = (int32_t)(seg->ack - c->snd_nxt);
            rst_ok = (lo >= 0) && (hi <= 0)
                  && (seg->seq == c->rcv_nxt);
        }
        if (!rst_ok) {
            /* Silently ignore — do NOT echo, that would aid probing. */
            return;
        }
        fire_close(c);
        c->state = TCP_CLOSED;
        return;
    }

    switch (c->state) {
    case TCP_SYN_RECEIVED:
        if ((seg->flags & TCPF_ACK) && seg->ack == c->snd_nxt) {
            c->snd_una = seg->ack;
            rtx_on_ack(c, seg->ack, now_ms);
            /* Set ESTABLISHED before firing on_open so that any send
             * the service issues from inside on_open (e.g. a server
             * greeting) passes the c->state == ESTABLISHED gate in
             * tcp_send_at. fire_open's refusal path resets state to
             * CLOSED before returning, so the worst-case observable
             * sequence (single-threaded stack) is
             *   ESTABLISHED -> CLOSED inside one tcp_input call,
             * which is identical to a normal RST teardown. Multi-
             * threaded use is NOT supported by this stack. */
            c->state = TCP_ESTABLISHED;

            /* Fire on_open EXACTLY at ESTABLISHED, not at SYN. This
             * prevents half-open connections from exhausting the
             * service's per-conn state pool (SYN-flood resistance). */
            if (c->svc && !fire_open(c, emit, emit_user)) return;

            /* Handle data piggybacked on the final ACK. */
            if (seg->payload_len) {
                if (c->svc) {
                    if (!drive_service_data(c, seg->payload, seg->payload_len,
                                            emit, emit_user)) return;
                } else if (on_data) {
                    on_data(c, seg->payload, seg->payload_len, on_data_user);
                }
                c->rcv_nxt += seg->payload_len;
                emit_ctrl(c, TCPF_ACK, emit, emit_user);
            }
        }
        break;

    case TCP_ESTABLISHED:
        /* Use signed delta so the comparison is correct across the
         * 32-bit seq wrap (RFC 1323 §4 / RFC 7323). */
        if ((int32_t)(seg->seq - c->rcv_nxt) != 0) {
            /* Out of order — re-ACK what we have and drop. */
            emit_ctrl(c, TCPF_ACK, emit, emit_user);
            return;
        }
        if (seg->flags & TCPF_ACK) {
            /* Track peer's advertised window for our send-window calc. */
            c->snd_wnd = seg->window ? seg->window : c->snd_wnd;
            /* RFC 5681 §2 dup-ack predicate: ack == snd_una AND
             * unacked data outstanding AND no payload AND no SYN/FIN.
             * Window changes also disqualify a dup, but we ignore
             * window field for simplicity. */
            int is_dup = (seg->ack == c->snd_una)
                      && (c->rtx_n > 0)
                      && (seg->payload_len == 0)
                      && ((seg->flags & (TCPF_SYN | TCPF_FIN)) == 0);
            int32_t adv = (int32_t)(seg->ack - c->snd_una);
            if (adv > 0) {
                uint32_t bytes_acked = (uint32_t)adv;
                c->snd_una = seg->ack;
                rtx_on_ack(c, seg->ack, now_ms);
                cc_on_new_ack(c, bytes_acked);
            } else if (is_dup) {
                cc_on_dupack(c, emit, emit_user);
            }
        }
        if (seg->payload_len) {
            uint16_t adv_wnd = tcp_advertised_wnd(c);
            /* Zero-window flow control: if we have advertised a zero
             * window, we MUST NOT consume the bytes. Any segment
             * arriving here is either:
             *   - a persist probe (RFC 9293 §3.8.6.1, typically 1
             *     byte) sent because our last ACK had wnd=0, or
             *   - a stale in-flight segment from before we closed
             *     the window.
             * In either case: drop the data, do NOT advance rcv_nxt,
             * and re-ACK with the current (still 0) window so the
             * peer keeps probing instead of giving up. */
            if (adv_wnd == 0) {
                emit_ctrl(c, TCPF_ACK, emit, emit_user);
                return;
            }
            /* Reject any segment that overruns the advertised receive
             * window. Previously we accepted the full payload and only
             * clamped rcv_buf_used, which let an aggressive sender
             * push past what the application could buffer. Drop +
             * re-ACK with current window so the peer retransmits
             * after we drain. */
            if (seg->payload_len > adv_wnd) {
                emit_ctrl(c, TCPF_ACK, emit, emit_user);
                return;
            }
            if (c->svc) {
                if (!drive_service_data(c, seg->payload, seg->payload_len,
                                        emit, emit_user)) return;
            } else if (on_data) {
                on_data(c, seg->payload, seg->payload_len, on_data_user);
            }
            c->rcv_nxt += seg->payload_len;
            /* Application has accepted these bytes into its buffer.
             * It must call tcp_rcv_consumed() once it has drained
             * them so the window can re-open. */
            if (c->rcv_buf_cap > 0) {
                c->rcv_buf_used += seg->payload_len;
            }
            emit_ctrl(c, TCPF_ACK, emit, emit_user);
        }
        if (seg->flags & TCPF_FIN) {
            c->rcv_nxt++;
            c->state = TCP_CLOSE_WAIT;
            emit_ctrl(c, TCPF_ACK, emit, emit_user);
            /* Application is expected to close fairly soon; emit our FIN now. */
            emit_ctrl(c, TCPF_FIN | TCPF_ACK, emit, emit_user);
            c->snd_nxt++;
            c->state = TCP_LAST_ACK;
            fire_close(c);
        }
        break;

    case TCP_LAST_ACK:
        if ((seg->flags & TCPF_ACK) && seg->ack == c->snd_nxt) {
            fire_close(c);   /* idempotent if already fired */
            c->state = TCP_CLOSED;
        }
        break;

    default:
        emit_rst(seg, emit, emit_user);
        break;
    }
}

int tcp_send(tcp_conn_t* c,
             const uint8_t* data, size_t len,
             tcp_emit_fn emit, void* emit_user) {
    return tcp_send_at(c, data, len, 0, emit, emit_user);
}

uint32_t tcp_flight_size(const tcp_conn_t* c) {
    if (!c) return 0;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < c->rtx_n; i++) sum += c->rtx[i].len;
    return sum;
}

uint32_t tcp_send_window(const tcp_conn_t* c) {
    if (!c) return 0;
    uint32_t cwnd = c->cwnd ? c->cwnd : TCP_INIT_CWND;
    uint32_t snd  = c->snd_wnd ? c->snd_wnd : 65535u;
    uint32_t lim  = (cwnd < snd) ? cwnd : snd;
    uint32_t fl   = tcp_flight_size(c);
    return (fl >= lim) ? 0 : (lim - fl);
}

/* RFC 5681 §3.1: cwnd growth on cumulative-ack progress. Slow start
 * (cwnd < ssthresh): cwnd += min(bytes_acked, MSS) per ACK.
 * Congestion avoidance: cwnd += MSS*MSS/cwnd per ACK (one MSS per RTT). */
static void cc_on_new_ack(tcp_conn_t* c, uint32_t bytes_acked) {
    if (bytes_acked == 0) return;
    /* Recovery exit: ack >= recovery_seq snapshotted at entry. We
     * detect via snd_una; caller has already advanced snd_una before
     * calling us, so just check the flag against the snapshot. */
    if (c->in_recovery) {
        if ((int32_t)(c->snd_una - c->recovery_seq) >= 0) {
            c->in_recovery  = 0;
            /* Deflate cwnd to ssthresh per RFC 5681 §3.2 step 6. */
            c->cwnd = c->ssthresh;
        }
        /* While in recovery NewReno keeps cwnd inflated; do not grow. */
        c->dupack_n = 0;
        return;
    }
    if (c->cwnd < c->ssthresh) {
        /* Slow start, RFC 5681 §3.1 (with abc=2 cap at one MSS). */
        uint32_t inc = (bytes_acked < TCP_MSS) ? bytes_acked : TCP_MSS;
        c->cwnd += inc;
    } else {
        /* Congestion avoidance, RFC 5681 §3.1. */
        uint32_t inc = (TCP_MSS * TCP_MSS) / (c->cwnd ? c->cwnd : 1u);
        if (inc == 0) inc = 1;
        c->cwnd += inc;
    }
    c->dupack_n = 0;
}

/* RFC 5681 §3.2: duplicate ACK. Increment counter; on 3rd dup,
 * enter fast retransmit/fast recovery: ssthresh = max(flight/2,
 * 2*MSS), cwnd = ssthresh + 3*MSS, retransmit oldest unacked. */
static void cc_on_dupack(tcp_conn_t* c, tcp_emit_fn emit, void* emit_user) {
    c->dupack_n++;
    if (c->dupack_n < TCP_DUPACK_THRESHOLD) return;
    if (c->in_recovery) {
        /* NewReno §3.2 step 4: in recovery, each further dupack
         * inflates cwnd by 1*MSS to allow new data to be sent. */
        c->cwnd += TCP_MSS;
        return;
    }
    /* Enter fast recovery. */
    uint32_t flight = tcp_flight_size(c);
    uint32_t half   = flight / 2u;
    c->ssthresh = (half >= TCP_MIN_CWND) ? half : TCP_MIN_CWND;
    c->cwnd     = c->ssthresh + 3u * TCP_MSS;
    c->recovery_seq = c->snd_nxt;
    c->in_recovery  = 1;
    /* Fast retransmit: resend oldest unacked. */
    if (c->rtx_n > 0 && emit) {
        tcp_rtx_entry_t* e = &c->rtx[0];
        c->rcv_wnd = tcp_advertised_wnd(c);
        tcp_seg_t seg = {0};
        seg.src_ip   = c->local_ip;
        seg.dst_ip   = c->remote_ip;
        seg.src_port = c->local_port;
        seg.dst_port = c->remote_port;
        seg.seq      = e->seq;
        seg.ack      = c->rcv_nxt;
        seg.flags    = e->flags;
        seg.window   = c->rcv_wnd;
        seg.payload  = e->payload;
        seg.payload_len = e->len;
        emit(&seg, emit_user);
        e->retrans = 1;        /* Karn: don't sample RTT now */
    }
}

/* RFC 5681 §3.1 step 4: RTO timeout collapses cwnd to 1*MSS,
 * sets ssthresh to max(flight/2, 2*MSS), exits recovery. Caller
 * (tcp_tick) handles the actual retransmit + RTO doubling. */
static void cc_on_rto(tcp_conn_t* c) {
    uint32_t flight = tcp_flight_size(c);
    uint32_t half   = flight / 2u;
    c->ssthresh = (half >= TCP_MIN_CWND) ? half : TCP_MIN_CWND;
    c->cwnd        = TCP_MSS;
    c->dupack_n    = 0;
    c->in_recovery = 0;
}

/* Append an entry to the retransmit queue. Returns 0 on success,
 * -1 if the queue is full (caller treats as a backpressure signal). */
static int rtx_enqueue(tcp_conn_t* c, uint32_t seq, uint32_t len,
                       const uint8_t* payload, uint8_t flags,
                       uint64_t tx_time_ms) {
    if (c->rtx_n >= TCP_RTX_QUEUE_MAX) return -1;
    tcp_rtx_entry_t* e = &c->rtx[c->rtx_n++];
    e->seq        = seq;
    e->len        = len;
    e->payload    = payload;
    e->flags      = flags;
    e->retrans    = 0;
    e->tx_time_ms = tx_time_ms;
    return 0;
}

/* Drop all entries whose (seq + len) is fully covered by ack_no.
 * For each non-retransmitted entry, take an RTT sample (RFC 6298 §3,
 * Karn's algorithm: skip retransmitted segments). */
static void rtx_on_ack(tcp_conn_t* c, uint32_t ack_no, uint64_t now_ms) {
    uint32_t w = 0;
    for (uint32_t r = 0; r < c->rtx_n; r++) {
        tcp_rtx_entry_t* e = &c->rtx[r];
        uint32_t end = e->seq + e->len;
        /* Partial-ack handling: if ack covers only part of a segment
         * we keep the entry (the spike never produces partial acks
         * because we don't segment, but be defensive). */
        if ((int32_t)(ack_no - end) < 0) {
            c->rtx[w++] = *e;
            continue;
        }
        /* Fully-acked. Maybe sample RTT. */
        if (!e->retrans && now_ms != 0 && now_ms >= e->tx_time_ms) {
            uint32_t r_ms = (uint32_t)(now_ms - e->tx_time_ms);
            if (c->srtt_ms == 0) {
                /* RFC 6298 §2.2: first measurement.
                 *   SRTT   = R
                 *   RTTVAR = R/2
                 *   RTO    = SRTT + max(G, K*RTTVAR), K=4, G=clock granularity
                 * G is taken as 1 ms here (we work in ms). */
                c->srtt_ms   = r_ms;
                c->rttvar_ms = r_ms / 2;
            } else {
                /* RFC 6298 §2.3: subsequent measurements.
                 *   RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
                 *   SRTT   = (1 - alpha) * SRTT + alpha * R'
                 * alpha = 1/8, beta = 1/4. */
                uint32_t diff = (c->srtt_ms > r_ms)
                                ? (c->srtt_ms - r_ms) : (r_ms - c->srtt_ms);
                c->rttvar_ms = (3u * c->rttvar_ms + diff) / 4u;
                c->srtt_ms   = (7u * c->srtt_ms   + r_ms) / 8u;
            }
            uint32_t kvar = 4u * c->rttvar_ms;
            if (kvar < 1u) kvar = 1u;       /* G = 1 ms */
            uint32_t rto  = c->srtt_ms + kvar;
            if (rto < TCP_RTO_MIN_MS) rto = TCP_RTO_MIN_MS;
            if (rto > TCP_RTO_MAX_MS) rto = TCP_RTO_MAX_MS;
            c->rto_ms = rto;
        }
    }
    c->rtx_n = w;
}

int tcp_send_at(tcp_conn_t* c,
                const uint8_t* data, size_t len,
                uint64_t now_ms,
                tcp_emit_fn emit, void* emit_user) {
    if (c->state != TCP_ESTABLISHED) return -1;
    /* If the caller opted into RTX (now_ms != 0) and the queue is
     * full, refuse the send so they can back off. */
    if (now_ms != 0 && c->rtx_n >= TCP_RTX_QUEUE_MAX) return -1;
    /* Congestion + flow control: refuse if the segment would exceed
     * the effective send window (min(cwnd, snd_wnd) - flight).
     * Caller is expected to retry once acks free up window. Only
     * applied to RTX-tracked sends; legacy now_ms=0 path bypasses
     * for back-compat. */
    if (now_ms != 0 && (uint32_t)len > tcp_send_window(c)) return -1;
    if (c->rto_ms == 0) c->rto_ms = TCP_RTO_INIT_MS;
    /* Refresh advertised window for the outbound. */
    c->rcv_wnd = tcp_advertised_wnd(c);
    tcp_seg_t s = {0};
    s.src_ip   = c->local_ip;
    s.dst_ip   = c->remote_ip;
    s.src_port = c->local_port;
    s.dst_port = c->remote_port;
    s.seq      = c->snd_nxt;
    s.ack      = c->rcv_nxt;
    s.flags    = TCPF_ACK | TCPF_PSH;
    s.window   = c->rcv_wnd;
    s.payload  = data;
    s.payload_len = len;
    emit(&s, emit_user);
    if (now_ms != 0 && len > 0) {
        /* The precondition at line ~644 already guarantees rtx_n <
         * MAX, so this enqueue cannot fail today. Check the return
         * anyway so a future change to the precondition can't silently
         * orphan a sent segment with no RTO recovery path. */
        if (rtx_enqueue(c, c->snd_nxt, (uint32_t)len, data,
                        TCPF_ACK | TCPF_PSH, now_ms) != 0) {
            return -1;
        }
    }
    c->snd_nxt += (uint32_t)len;
    return (int)len;
}

void tcp_tick(tcp_stack_t* s, uint64_t now_ms,
              tcp_emit_fn emit, void* emit_user) {
    if (!s) return;
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        tcp_conn_t* c = &s->conns[i];
        if (c->state != TCP_ESTABLISHED && c->state != TCP_CLOSE_WAIT) continue;
        if (c->rtx_n == 0) continue;
        tcp_rtx_entry_t* e = &c->rtx[0];     /* oldest unacked */
        uint64_t age = (now_ms >= e->tx_time_ms) ? (now_ms - e->tx_time_ms) : 0;
        if (age < c->rto_ms) continue;
        /* Retransmit. Refresh window (peer may have opened RX). */
        c->rcv_wnd = tcp_advertised_wnd(c);
        tcp_seg_t seg = {0};
        seg.src_ip   = c->local_ip;
        seg.dst_ip   = c->remote_ip;
        seg.src_port = c->local_port;
        seg.dst_port = c->remote_port;
        seg.seq      = e->seq;
        seg.ack      = c->rcv_nxt;
        seg.flags    = e->flags;
        seg.window   = c->rcv_wnd;
        seg.payload  = e->payload;
        seg.payload_len = e->len;
        emit(&seg, emit_user);
        e->retrans    = 1;
        e->tx_time_ms = now_ms;
        /* RFC 5681 §3.1 step 4: collapse cwnd, halve ssthresh. */
        cc_on_rto(c);
        /* RFC 6298 §5.5: double RTO on timeout, cap at RTO_MAX. */
        uint64_t doubled = (uint64_t)c->rto_ms * 2u;
        if (doubled > TCP_RTO_MAX_MS) doubled = TCP_RTO_MAX_MS;
        c->rto_ms = (uint32_t)doubled;
    }
}

int tcp_sendv(tcp_conn_t* c,
              const pw_iov_t* iov, unsigned n,
              tcp_emit_fn emit, void* emit_user) {
    if (c->state != TCP_ESTABLISHED) return -1;
    if (n == 0)                      return 0;

    /* Total length is computed UP FRONT - the property the user wants
     * for the layered pipeline ("calculate length before TLS is hit").
     *
     * For the spike we coalesce into one segment; if total exceeds
     * MSS the caller is responsible for pre-segmenting. The layered
     * architecture in DESIGN.md notes this constraint. */
    size_t total = 0;
    for (unsigned i = 0; i < n; i++) total += iov[i].len;

    /* If single fragment, just call tcp_send and skip the staging. */
    if (n == 1) {
        return tcp_send(c, iov[0].base, iov[0].len, emit, emit_user);
    }

    /* Multi-fragment path: stage into a per-conn scratch buffer. We
     * deliberately keep this small and non-allocating - the iov
     * pipeline's whole point is to AVOID this copy by emitting one
     * fragment per segment when the underlying I/O supports
     * scatter-gather (writev/sendmsg/io_uring/rte_mbuf chain).
     *
     * For the in-tree tcp_emit_fn (which takes a single payload
     * pointer), we have to coalesce. Real I/O backends should bypass
     * this and use sendmsg/writev directly with iov[].
     */
    static uint8_t scratch[16 * 1024];
    if (total > sizeof(scratch)) return -1;
    size_t off = 0;
    for (unsigned i = 0; i < n; i++) {
        memcpy(scratch + off, iov[i].base, iov[i].len);
        off += iov[i].len;
    }
    return tcp_send(c, scratch, total, emit, emit_user);
}
