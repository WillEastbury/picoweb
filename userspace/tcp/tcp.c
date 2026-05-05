/*
 * Minimal TCP state machine — passive open, happy path only.
 *
 * NOT a production stack. See tcp.h for the explicit exclusions.
 */

#include "tcp.h"

#include <string.h>

static tcp_conn_t* find_conn(tcp_stack_t* s, const tcp_seg_t* seg) {
    for (uint32_t i = 0; i < TCP_TABLE_SIZE; i++) {
        tcp_conn_t* c = &s->conns[i];
        if (c->state == TCP_CLOSED) continue;
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

void tcp_input(tcp_stack_t* s, const tcp_seg_t* seg,
               tcp_on_data_fn on_data, void* on_data_user,
               tcp_emit_fn emit, void* emit_user) {
    /* Reject if not addressed to our listen IP+port. */
    if (seg->dst_ip != s->local_ip || seg->dst_port != s->listen_port) {
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
        emit_ctrl(c, TCPF_SYN | TCPF_ACK, emit, emit_user);
        c->snd_nxt++;                      /* +1 for our SYN */
        return;
    }

    /* RST always tears down. */
    if (seg->flags & TCPF_RST) { c->state = TCP_CLOSED; return; }

    switch (c->state) {
    case TCP_SYN_RECEIVED:
        if ((seg->flags & TCPF_ACK) && seg->ack == c->snd_nxt) {
            c->snd_una = seg->ack;
            c->state = TCP_ESTABLISHED;
            /* fall through to handle data piggybacked on the ACK */
            if (seg->payload_len) {
                if (on_data) on_data(c, seg->payload, seg->payload_len, on_data_user);
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
            if (on_data) on_data(c, seg->payload, seg->payload_len, on_data_user);
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
        }
        break;

    case TCP_LAST_ACK:
        if ((seg->flags & TCPF_ACK) && seg->ack == c->snd_nxt) {
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
