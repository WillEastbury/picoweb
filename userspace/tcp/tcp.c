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

static void emit_ctrl(tcp_conn_t* c, uint8_t flags,
                      tcp_emit_fn emit, void* user) {
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
        c->snd_nxt     = 0xc0fe0000u;      /* deterministic ISS for spike */
        c->snd_una     = c->snd_nxt;
        c->rcv_wnd     = 65535;
        c->svc         = svc;              /* may be NULL in legacy mode */
        c->app_state   = NULL;
        c->opened      = 0;
        emit_ctrl(c, TCPF_SYN | TCPF_ACK, emit, emit_user);
        c->snd_nxt++;                      /* +1 for our SYN */
        return;
    }

    /* RST always tears down. */
    if (seg->flags & TCPF_RST) {
        fire_close(c);
        c->state = TCP_CLOSED;
        return;
    }

    switch (c->state) {
    case TCP_SYN_RECEIVED:
        if ((seg->flags & TCPF_ACK) && seg->ack == c->snd_nxt) {
            c->snd_una = seg->ack;
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
        if (seg->seq != c->rcv_nxt) {
            /* Out of order — re-ACK what we have and drop. */
            emit_ctrl(c, TCPF_ACK, emit, emit_user);
            return;
        }
        if (seg->flags & TCPF_ACK) c->snd_una = seg->ack;
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
    if (c->state != TCP_ESTABLISHED) return -1;
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
    c->snd_nxt += (uint32_t)len;
    return (int)len;
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
