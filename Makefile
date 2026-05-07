# picoweb Makefile
CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wshadow -Wpedantic -std=c11 -D_GNU_SOURCE \
           -fno-strict-aliasing -fstack-protector-strong \
           -flto -march=native -fomit-frame-pointer
LDFLAGS ?= -flto -O3
LDLIBS  ?= -pthread

# All backends are compiled into a single binary; main.c picks
# between epoll / io_uring / dpdk at runtime via:
#   ./picoweb              (epoll, default)
#   ./picoweb --io_uring   (io_uring; Linux 5.6+, no liburing)
#   ./picoweb --dpdk       (stub: errors out — DPDK backend not built;
#                           see userspace/DESIGN.md)
USERSPACE_TLS_SRC := \
	userspace/conn.c \
	userspace/dispatch.c \
	userspace/tcp/ip.c \
	userspace/tcp/tcp.c \
	userspace/io/af_packet.c \
	userspace/io/af_xdp.c \
	userspace/crypto/util.c \
	userspace/crypto/cpuid.c \
	userspace/crypto/sha256.c \
	userspace/crypto/sha256_shani.c \
	userspace/crypto/sha256_armv8.c \
	userspace/crypto/sha512.c \
	userspace/crypto/ed25519.c \
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

SRC := $(wildcard src/*.c) $(USERSPACE_TLS_SRC)
OBJ := $(SRC:.c=.o)
BIN := picoweb

.PHONY: all clean run debug

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wshadow -Wpedantic -std=c11 \
                 -D_GNU_SOURCE -fno-strict-aliasing \
                 -fsanitize=address,undefined
debug: LDLIBS += -fsanitize=address,undefined
debug: LDFLAGS :=
debug: clean $(BIN)

run: $(BIN)
	./$(BIN) 8080 wwwroot

clean:
	rm -f src/*.o picoweb picoweb_uring
