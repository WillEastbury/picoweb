#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "xdp_loader.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>

/* eBPF instruction convenience macros (not in userspace headers). */
#define BPF_ALU64  0x07
#define BPF_DW     0x18
#define BPF_XADD   0xc0

#define INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){.code=(CODE), .dst_reg=(DST), .src_reg=(SRC), .off=(OFF), .imm=(IMM)})

#define BPF_MOV64_REG(D,S)   INSN(BPF_ALU64|BPF_MOV|BPF_X, D, S, 0, 0)
#define BPF_MOV64_IMM(D,I)   INSN(BPF_ALU64|BPF_MOV|BPF_K, D, 0, 0, I)
#define BPF_LDX_MEM_W(D,S,O) INSN(BPF_LDX|BPF_W|BPF_MEM,  D, S, O, 0)
#define BPF_LDX_MEM_H(D,S,O) INSN(BPF_LDX|BPF_H|BPF_MEM,  D, S, O, 0)
#define BPF_LDX_MEM_B(D,S,O) INSN(BPF_LDX|BPF_B|BPF_MEM,  D, S, O, 0)
#define BPF_ALU64_IMM(OP,D,I) INSN(BPF_ALU64|(OP)|BPF_K, D, 0, 0, I)
#define BPF_JMP_REG(OP,D,S,O) INSN(BPF_JMP|(OP)|BPF_X, D, S, O, 0)
#define BPF_JMP_IMM(OP,D,I,O) INSN(BPF_JMP|(OP)|BPF_K, D, 0, O, I)
#define BPF_CALL_FUNC(F)       INSN(BPF_JMP|BPF_CALL, 0, 0, 0, F)
#define BPF_INSN_EXIT()        INSN(BPF_JMP|0x90, 0, 0, 0, 0)
/* 64-bit immediate load (2 insns) */
#define BPF_LD_MAP_FD(D, FD) \
    INSN(BPF_LD|BPF_DW|BPF_IMM, D, 1, 0, (uint32_t)(FD)), \
    INSN(0, 0, 0, 0, 0)

/* BPF register names */
#define R0  0
#define R1  1
#define R2  2
#define R3  3
#define R4  4
#define R5  5
#define R6  6
#define R7  7
#define R8  8
#define R9  9
#define R10 10

/* BPF helper function IDs */
#define BPF_FUNC_redirect_map 51

/* xdp_md field offsets */
#define XDP_MD_DATA      0
#define XDP_MD_DATA_END  4

/* Protocol constants */
#define ETH_P_IP_BE   0x0008  /* 0x0800 in network byte order on LE */
#define IPPROTO_TCP_V 6

static inline int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static int create_xskmap(void) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type    = BPF_MAP_TYPE_XSKMAP;
    attr.key_size    = 4;
    attr.value_size  = 4;
    attr.max_entries = 1;
    strncpy(attr.map_name, "xsk_map", sizeof(attr.map_name));
    return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int load_xdp_prog(int map_fd, uint16_t port) {
    uint16_t port_be = htons(port);

    /*
     * XDP program: redirect TCP:port to xsk_map[0], pass everything else.
     * Assumes standard IP header (IHL=5, no options) — covers 99.9% of traffic.
     * TCP dest port at byte offset 36 (eth:14 + IP:20 + dport_offset:2).
     */
    struct bpf_insn insns[] = {
        /* 0 */ BPF_MOV64_REG(R6, R1),
        /* 1 */ BPF_LDX_MEM_W(R1, R6, XDP_MD_DATA),
        /* 2 */ BPF_LDX_MEM_W(R2, R6, XDP_MD_DATA_END),
        /* 3 */ BPF_MOV64_REG(R3, R1),
        /* 4 */ BPF_ALU64_IMM(BPF_ADD, R3, 54),
        /* 5 */ BPF_JMP_REG(BPF_JGT, R3, R2, 12),
        /* 6 */ BPF_LDX_MEM_H(R4, R1, 12),
        /* 7 */ BPF_JMP_IMM(BPF_JNE, R4, ETH_P_IP_BE, 10),
        /* 8 */ BPF_LDX_MEM_B(R4, R1, 23),
        /* 9 */ BPF_JMP_IMM(BPF_JNE, R4, IPPROTO_TCP_V, 8),
        /*10 */ BPF_LDX_MEM_H(R4, R1, 36),
        /*11 */ BPF_JMP_IMM(BPF_JNE, R4, port_be, 6),
        /*12 */ BPF_LD_MAP_FD(R1, map_fd),  /* 2 insns: 12, 13 */
        /*14 */ BPF_MOV64_IMM(R2, 0),
        /*15 */ BPF_MOV64_IMM(R3, 2),
        /*16 */ BPF_CALL_FUNC(BPF_FUNC_redirect_map),
        /*17 */ BPF_INSN_EXIT(),
        /*18 */ BPF_MOV64_IMM(R0, 2),
        /*19 */ BPF_INSN_EXIT(),
    };

    char log_buf[4096];
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type    = BPF_PROG_TYPE_XDP;
    attr.insn_cnt     = sizeof(insns) / sizeof(insns[0]);
    attr.insns        = (uint64_t)(unsigned long)insns;
    attr.license      = (uint64_t)(unsigned long)"GPL";
    attr.log_buf      = (uint64_t)(unsigned long)log_buf;
    attr.log_size     = sizeof(log_buf);
    attr.log_level    = 1;
    strncpy(attr.prog_name, "xdp_redir_443", sizeof(attr.prog_name));

    int fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        /* Retry without log for kernels that reject log_level on success path */
        attr.log_level = 0;
        attr.log_buf   = 0;
        attr.log_size  = 0;
        fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    }
    return fd;
}

static int attach_xdp(int ifindex, int prog_fd) {
    /* Use netlink to attach XDP program in SKB (generic) mode.
     * Alternatively, use BPF_LINK_CREATE (kernel 5.9+). */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.link_create.prog_fd       = prog_fd;
    attr.link_create.target_ifindex = ifindex;
    attr.link_create.attach_type   = 37; /* BPF_XDP */
    attr.link_create.flags         = XDP_FLAGS_SKB_MODE;

    int link_fd = sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
    if (link_fd >= 0) return link_fd;

    /* Fallback: netlink-based XDP attach */

    /* Netlink-based attach */
    int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock < 0) return -1;

    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifm;
        char             buf[256];
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type  = RTM_SETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifm.ifi_family  = AF_UNSPEC;
    req.ifm.ifi_index   = ifindex;

    /* Add IFLA_XDP nested attribute */
    struct rtattr *xdp_rta = (struct rtattr *)
        ((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    xdp_rta->rta_type = 43; /* IFLA_XDP */
    xdp_rta->rta_len  = RTA_LENGTH(0); /* updated below */

    char *nest_data = (char *)RTA_DATA(xdp_rta);
    /* IFLA_XDP_FD */
    struct rtattr *fd_rta = (struct rtattr *)nest_data;
    fd_rta->rta_type = 1; /* IFLA_XDP_FD */
    fd_rta->rta_len  = RTA_LENGTH(sizeof(int));
    memcpy(RTA_DATA(fd_rta), &prog_fd, sizeof(int));
    nest_data += RTA_ALIGN(fd_rta->rta_len);

    /* IFLA_XDP_FLAGS */
    struct rtattr *flags_rta = (struct rtattr *)nest_data;
    flags_rta->rta_type = 3; /* IFLA_XDP_FLAGS */
    uint32_t xdp_flags = XDP_FLAGS_SKB_MODE;
    flags_rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
    memcpy(RTA_DATA(flags_rta), &xdp_flags, sizeof(uint32_t));
    nest_data += RTA_ALIGN(flags_rta->rta_len);

    xdp_rta->rta_len = (uint16_t)(nest_data - (char *)xdp_rta);
    req.nlh.nlmsg_len = (uint32_t)(nest_data - (char *)&req);

    int ret = (int)send(sock, &req, req.nlh.nlmsg_len, 0);
    if (ret < 0) { close(sock); return -1; }

    /* Read ACK */
    char resp[512];
    int n = (int)recv(sock, resp, sizeof(resp), 0);
    close(sock);

    struct nlmsghdr *nlh = (struct nlmsghdr *)resp;
    if (n < (int)sizeof(*nlh) || nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (n >= (int)(sizeof(*nlh) + sizeof(*err)) && err->error != 0)
            return -1;
    }
    return 0; /* attached via netlink */
}

int xdp_load_redirect(int ifindex, uint16_t port) {
    int map_fd = create_xskmap();
    if (map_fd < 0) return -1;

    int prog_fd = load_xdp_prog(map_fd, port);
    if (prog_fd < 0) { close(map_fd); return -1; }

    int ret = attach_xdp(ifindex, prog_fd);
    close(prog_fd); /* program stays attached via refcount */
    if (ret < 0) { close(map_fd); return -1; }

    return map_fd;
}

void xdp_unload(int ifindex, int map_fd) {
    /* Detach XDP by setting fd=-1 via netlink */
    int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock < 0) { close(map_fd); return; }

    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifm;
        char             buf[128];
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type  = RTM_SETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifm.ifi_family  = AF_UNSPEC;
    req.ifm.ifi_index   = ifindex;

    struct rtattr *xdp_rta = (struct rtattr *)
        ((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    xdp_rta->rta_type = 43; /* IFLA_XDP */

    char *nest_data = (char *)RTA_DATA(xdp_rta);
    struct rtattr *fd_rta = (struct rtattr *)nest_data;
    fd_rta->rta_type = 1; /* IFLA_XDP_FD */
    fd_rta->rta_len  = RTA_LENGTH(sizeof(int));
    int neg = -1;
    memcpy(RTA_DATA(fd_rta), &neg, sizeof(int));
    nest_data += RTA_ALIGN(fd_rta->rta_len);

    xdp_rta->rta_len = (uint16_t)(nest_data - (char *)xdp_rta);
    req.nlh.nlmsg_len = (uint32_t)(nest_data - (char *)&req);

    send(sock, &req, req.nlh.nlmsg_len, 0);
    char resp[512];
    recv(sock, resp, sizeof(resp), 0);
    close(sock);
    close(map_fd);
}
