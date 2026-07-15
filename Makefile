# picoweb Makefile
#
# picoweb/picowal trace their lineage to an RP2350 (embedded) server design;
# this build gates the desktop/server-only performance extras (io_uring, the
# legacy AF_PACKET/AF_XDP userspace TCP+TLS stack) behind opt-in flags instead
# of requiring them unconditionally, so the CORE build (epoll HTTP + kernel-
# socket TLS + picowal WAL/query/schema engine) stays buildable with a plain
# POSIX toolchain. See docs/PICOSCRIPT_UNIFIED_RUNTIME.md (picoscript repo)
# for the parallel portable-core path (vm/picovm_pool.c) that additionally
# targets Windows and PIOS/RP2350, where even epoll isn't available.
CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wshadow -Wpedantic -std=c11 -D_GNU_SOURCE \
           -fno-strict-aliasing -fstack-protector-strong \
           -flto -fomit-frame-pointer
LDFLAGS ?= -flto -O3
LDLIBS  ?= -pthread

# Opt-in feature flags (all default OFF/auto so a plain POSIX toolchain
# without liburing headers or the legacy raw-packet stack still builds the
# full HTTP+HTTPS+picowal core):
#   NATIVE_ARCH=1       -march=native (ties the binary to the build host's CPU;
#                       off by default -- SIMD crypto (SHA-NI/AVX) already uses
#                       per-file `#pragma GCC target` + runtime CPUID dispatch
#                       via userspace/crypto/pw_cpuid.c, so this is a pure perf
#                       knob, never required for correctness).
#   WITH_URING=1        build server_uring.c (Linux 5.6+ io_uring backend;
#                       requires <linux/io_uring.h> -- auto-detected below).
#   WITH_LEGACY_XDP=1   build the legacy AF_PACKET/AF_XDP userspace TCP+TLS
#                       backend (server_tls.c + userspace/conn.c, dispatch.c,
#                       tcp/*.c, io/af_packet.c, io/af_xdp.c, xdp/xdp_loader.c).
#                       Superseded by the kernel-socket TLS path
#                       (server_tls_kernel.c, always built) which is what
#                       --tls actually runs today; these files are unreferenced
#                       by the default binary otherwise. Mutually exclusive
#                       with the default TLS path (both define
#                       tls_worker_main), so enabling this switches --tls to
#                       the legacy AF_XDP path instead of the kernel-socket one.
NATIVE_ARCH     ?= 0
WITH_URING      ?= $(shell test -f /usr/include/linux/io_uring.h && echo 1 || echo 0)
WITH_LEGACY_XDP ?= 0

ifeq ($(NATIVE_ARCH),1)
CFLAGS += -march=native
endif

# All backends are compiled into a single binary; main.c picks
# between epoll / io_uring / dpdk at runtime via:
#   ./picoweb              (epoll, default)
#   ./picoweb --io_uring   (io_uring; Linux 5.6+, no liburing; requires WITH_URING=1 at build time)
#   ./picoweb --dpdk       (stub: errors out — DPDK backend not built;
#                           see userspace/DESIGN.md)
#   ./picoweb --tls        (kernel-socket TLS by default; legacy AF_XDP path if WITH_LEGACY_XDP=1)

# Core TLS engine (crypto + handshake), needed by the default kernel-socket
# TLS backend (server_tls_kernel.c) -- always built, not gated.
USERSPACE_TLS_ENGINE_SRC := \
	userspace/crypto/util.c \
	userspace/crypto/pw_cpuid.c \
	userspace/crypto/sha256.c \
	userspace/crypto/sha256_shani.c \
	userspace/crypto/sha256_armv8.c \
	userspace/crypto/sha512.c \
	userspace/crypto/ed25519.c \
	userspace/crypto/rsa.c \
	userspace/crypto/p256.c \
	userspace/crypto/ecdsa.c \
	userspace/crypto/hmac.c \
	userspace/crypto/hkdf.c \
	userspace/crypto/chacha20.c \
	userspace/crypto/chacha20_sse2.c \
	userspace/crypto/poly1305.c \
	userspace/crypto/chacha20_poly1305.c \
	userspace/crypto/x25519.c \
	userspace/tls/keysched.c \
	userspace/tls/record.c \
	userspace/tls/pem.c \
	userspace/tls/cert.c \
	userspace/tls/handshake.c \
	userspace/tls/engine.c \
	userspace/tls/ticket_store.c

# Legacy AF_PACKET/AF_XDP raw-packet userspace TCP+TLS stack. Currently
# unreferenced by anything in the default binary except server_tls.c itself
# (confirmed: grepping every file the default SRC list pulls in for
# af_packet/af_xdp/xdp_loader/userspace/conn/dispatch/tcp comes back empty) --
# gated behind WITH_LEGACY_XDP so it isn't compiled for no reason.
USERSPACE_LEGACY_XDP_SRC := \
	src/server_tls.c \
	userspace/conn.c \
	userspace/dispatch.c \
	userspace/tcp/ip.c \
	userspace/tcp/tcp.c \
	userspace/io/af_packet.c \
	userspace/io/af_xdp.c \
	userspace/xdp/xdp_loader.c

ALL_SRC := $(wildcard src/*.c) $(wildcard src/pico/*.c)
# picocompress.c is superseded (see src/pico/); server_tls.c is the legacy
# AF_XDP path, gated separately below.
SRC := $(filter-out src/server_tls.c src/pico/picocompress.c,$(ALL_SRC)) $(USERSPACE_TLS_ENGINE_SRC)

ifeq ($(WITH_URING),1)
CFLAGS += -DPICOWEB_WITH_URING
else
SRC := $(filter-out src/server_uring.c,$(SRC))
endif

ifeq ($(WITH_LEGACY_XDP),1)
# Re-add the legacy path. server_tls_kernel.c and server_tls.c both define
# tls_worker_main -- pick one at a time. Legacy mode replaces the kernel-socket
# TLS backend with the AF_PACKET/AF_XDP one (matches historical behaviour).
SRC := $(filter-out src/server_tls_kernel.c,$(SRC)) $(USERSPACE_LEGACY_XDP_SRC)
endif

OBJ := $(SRC:.c=.o)
DEP := $(OBJ:.o=.d)
BIN := picoweb

.PHONY: all clean run debug print-config

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/brotli.o: src/brotli.c
	$(CC) $(CFLAGS) -MMD -MP -fno-lto -O1 -c -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wshadow -Wpedantic -std=c11 \
                 -D_GNU_SOURCE -fno-strict-aliasing \
                 -fsanitize=address,undefined
debug: LDLIBS += -fsanitize=address,undefined
debug: LDFLAGS :=
debug: clean $(BIN)

run: $(BIN)
	./$(BIN) 8080 wwwroot

# Show the resolved feature-flag configuration for this build (useful before
# `make` on a new host to confirm what will/won't be compiled in).
print-config:
	@echo "NATIVE_ARCH=$(NATIVE_ARCH)  WITH_URING=$(WITH_URING)  WITH_LEGACY_XDP=$(WITH_LEGACY_XDP)"

clean:
	rm -f src/*.o src/*.d src/pico/*.o src/pico/*.d userspace/*.o userspace/*.d userspace/*/*.o userspace/*/*.d picoweb picoweb_uring

-include $(DEP)
