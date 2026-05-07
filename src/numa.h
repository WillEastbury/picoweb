#ifndef METAL_NUMA_H
#define METAL_NUMA_H

#include <stddef.h>
#include <stdbool.h>

/* Lightweight NUMA helpers — no libnuma dependency. All functions are
 * best-effort: on a non-Linux build, on a kernel without /sys/devices/
 * system/node, or in a container where the syscalls are filtered, they
 * return safe single-node defaults and the caller's behaviour is
 * unchanged. */

/* Number of online NUMA nodes (>=1). Reads /sys/devices/system/node/online.
 * Returns 1 if topology cannot be read. */
int  numa_online_node_count(void);

/* Highest online node id. -1 if topology cannot be read. Used to size
 * a node-bit nodemask for mbind. */
int  numa_max_online_node(void);

/* NUMA node hosting CPU `cpu`, by parsing the symlink at
 * /sys/devices/system/cpu/cpu<cpu>/. Returns -1 on failure. */
int  numa_cpu_to_node(int cpu);

/* mbind the page range [mem, mem+len) with MPOL_INTERLEAVE across all
 * online nodes. Returns true on success. Pages must not have been
 * touched yet for the policy to apply to first-touch allocations.
 * No-op (returns true) on single-node systems. Best-effort: failure
 * is logged but not fatal — caller continues with default policy. */
bool numa_interleave_all(void* mem, size_t len);

/* mbind the page range [mem, mem+len) to a specific NUMA node. Same
 * caveats as numa_interleave_all. */
bool numa_bind_node(void* mem, size_t len, int node);

#endif
