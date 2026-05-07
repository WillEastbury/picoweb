#include "numa.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#  include <sys/syscall.h>
#  include <linux/mempolicy.h>
#  ifndef MPOL_F_STATIC_NODES
#    define MPOL_F_STATIC_NODES (1 << 15)
#  endif
#endif

/* mbind() is not exposed via glibc on all distros (libnuma normally
 * wraps it). Call the raw syscall directly. Numbers per asm-generic
 * unistd: __NR_mbind = 235 on aarch64/x86_64. */
#if defined(__linux__) && defined(SYS_mbind)
static long do_mbind(void* addr, unsigned long len, int mode,
                     const unsigned long* nodemask, unsigned long maxnode,
                     unsigned flags) __attribute__((unused));
static long do_mbind(void* addr, unsigned long len, int mode,
                     const unsigned long* nodemask, unsigned long maxnode,
                     unsigned flags) {
    return syscall(SYS_mbind, addr, len, mode, nodemask, maxnode, flags);
}
#else
static long do_mbind(void* addr, unsigned long len, int mode,
                     const unsigned long* nodemask, unsigned long maxnode,
                     unsigned flags) {
    (void)addr; (void)len; (void)mode; (void)nodemask;
    (void)maxnode; (void)flags;
    errno = ENOSYS;
    return -1;
}
#endif

/* Parse a list expression like "0", "0-3", "0,2-4,7". Sets bits in
 * out_mask (a uint64_t array of capacity max_words) and returns the
 * highest bit set + 1, or 0 on error. */
static size_t parse_list(const char* s, unsigned long* out_mask,
                         size_t max_words, int* out_max_node) {
    int max_node = -1;
    while (*s && *s != '\n') {
        char* end;
        long a = strtol(s, &end, 10);
        if (end == s || a < 0) return 0;
        long b = a;
        s = end;
        if (*s == '-') {
            s++;
            b = strtol(s, &end, 10);
            if (end == s || b < a) return 0;
            s = end;
        }
        for (long n = a; n <= b; n++) {
            size_t word = (size_t)n / (8 * sizeof(unsigned long));
            size_t bit  = (size_t)n % (8 * sizeof(unsigned long));
            if (word >= max_words) return 0;
            out_mask[word] |= 1UL << bit;
            if ((int)n > max_node) max_node = (int)n;
        }
        if (*s == ',') s++;
    }
    if (out_max_node) *out_max_node = max_node;
    return (size_t)(max_node + 1);
}

static bool read_first_line(const char* path, char* buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return true;
}

int numa_online_node_count(void) {
    char buf[256];
    if (!read_first_line("/sys/devices/system/node/online", buf, sizeof(buf)))
        return 1;
    unsigned long mask[8] = {0};
    int max_node = -1;
    if (parse_list(buf, mask, 8, &max_node) == 0) return 1;
    int count = 0;
    for (size_t w = 0; w < 8; w++) {
        unsigned long v = mask[w];
        while (v) { v &= v - 1; count++; }
    }
    return count > 0 ? count : 1;
}

int numa_max_online_node(void) {
    char buf[256];
    if (!read_first_line("/sys/devices/system/node/online", buf, sizeof(buf)))
        return -1;
    unsigned long mask[8] = {0};
    int max_node = -1;
    if (parse_list(buf, mask, 8, &max_node) == 0) return -1;
    return max_node;
}

int numa_cpu_to_node(int cpu) {
    if (cpu < 0) return -1;
    /* Try /sys/devices/system/cpu/cpuN/node for a quick numeric. The
     * directory holds a symlink "node<M>" — open it as a directory,
     * scan entries for a "nodeN" prefix. Cheap fallback if the
     * directory listing helper isn't worth pulling in: try common
     * node ids 0..63 looking for the symlink "node<i>". */
    char path[256];
    for (int i = 0; i < 64; i++) {
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/node%d", cpu, i);
        if (access(path, F_OK) == 0) return i;
    }
    return -1;
}

bool numa_interleave_all(void* mem, size_t len) {
    if (numa_online_node_count() <= 1) return true;  /* no-op */
#if defined(__linux__) && defined(MPOL_INTERLEAVE)
    int max_node = numa_max_online_node();
    if (max_node < 0) return false;
    /* Build the nodemask from /sys/devices/system/node/online so we
     * interleave only across actually-online nodes (some VMs expose
     * gaps). maxnode argument is "highest node id + 1". */
    char buf[256];
    if (!read_first_line("/sys/devices/system/node/online", buf, sizeof(buf)))
        return false;
    unsigned long mask[8] = {0};
    int dummy = -1;
    if (parse_list(buf, mask, 8, &dummy) == 0) return false;
    long rc = do_mbind(mem, len, MPOL_INTERLEAVE,
                       mask, (unsigned long)(max_node + 1), 0);
    if (rc != 0) {
        metal_log("numa_interleave_all: mbind failed: %s", strerror(errno));
        return false;
    }
    return true;
#else
    (void)mem; (void)len;
    return false;
#endif
}

bool numa_bind_node(void* mem, size_t len, int node) {
    if (node < 0) return false;
    if (numa_online_node_count() <= 1) return true;  /* no-op */
#if defined(__linux__) && defined(MPOL_BIND)
    unsigned long mask[8] = {0};
    size_t word = (size_t)node / (8 * sizeof(unsigned long));
    size_t bit  = (size_t)node % (8 * sizeof(unsigned long));
    if (word >= 8) return false;
    mask[word] = 1UL << bit;
    long rc = do_mbind(mem, len, MPOL_BIND,
                       mask, (unsigned long)(node + 1), 0);
    if (rc != 0) {
        metal_log("numa_bind_node: mbind(node=%d) failed: %s", node, strerror(errno));
        return false;
    }
    return true;
#else
    (void)mem; (void)len; (void)node;
    return false;
#endif
}
