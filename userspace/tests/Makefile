# picoweb userspace TCP+TLS spike — test runner
#
# Standalone Makefile so the spike can build/test without touching
# the main picoweb build. Crypto is the only thing actually unit-
# tested in the spike right now; TCP/TLS state machines are
# scaffolding.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wshadow -std=c11 -D_GNU_SOURCE -I..
LDFLAGS ?=

CRYPTO_SRC := \
    ../crypto/util.c             \
    ../crypto/cpuid.c            \
    ../crypto/sha256.c           \
    ../crypto/sha256_shani.c     \
    ../crypto/sha256_armv8.c     \
    ../crypto/sha512.c           \
    ../crypto/ed25519.c          \
    ../crypto/rsa.c              \
    ../crypto/pool.c             \
    ../crypto/hmac.c             \
    ../crypto/hkdf.c             \
    ../crypto/chacha20.c         \
    ../crypto/chacha20_sse2.c    \
    ../crypto/poly1305.c         \
    ../crypto/chacha20_poly1305.c \
    ../crypto/x25519.c           \
    ../tls/keysched.c            \
    ../tls/record.c              \
    ../tls/pem.c                 \
    ../tls/cert.c                \
    ../tls/handshake.c           \
    ../tls/engine.c              \
    ../tls/engine_pool.c         \
    ../tls/ticket_store.c        \
    ../io/dpdk.c                 \
    ../tcp/ip.c                  \
    ../tcp/tcp.c                 \
    ../dispatch.c                \
    ../conn.c

QUIC_PRIM_SRC := \
    ../udp/udp.c                 \
    ../tcp/ip.c                  \
    ../crypto/util.c             \
    ../crypto/cpuid.c            \
    ../crypto/sha256.c           \
    ../crypto/sha256_shani.c     \
    ../crypto/sha256_armv8.c     \
    ../crypto/sha512.c           \
    ../crypto/ed25519.c          \
    ../crypto/rsa.c              \
    ../crypto/hmac.c             \
    ../crypto/hkdf.c             \
    ../crypto/aes.c              \
    ../crypto/aes_gcm.c          \
    ../tls/keysched.c            \
    ../tls/handshake.c           \
    ../quic/varint.c             \
    ../quic/initial.c            \
    ../quic/packet.c             \
    ../quic/frames.c             \
    ../quic/loss.c               \
    ../quic/cc.c                 \
    ../quic/flow.c               \
    ../quic/special.c            \
    ../quic/transport_params.c   \
    ../quic/crypto_stream.c      \
    ../quic/stream.c             \
    ../quic/keys.c               \
    ../quic/tls_ext.c            \
    ../quic/conn.c               \
    ../quic/handshake_driver.c   \
    ../h3/h3.c                   \
    ../qpack/qpack.c             \
    ../crypto/x25519.c

.PHONY: all clean test

all: test_crypto test_quic_primitives test_preload

test_crypto: test_crypto.c $(CRYPTO_SRC)
	$(CC) $(CFLAGS) -o $@ $^

test_quic_primitives: test_quic_primitives.c $(QUIC_PRIM_SRC)
	$(CC) $(CFLAGS) -o $@ $^

test_preload: test_preload.c ../../src/preload.c
	$(CC) $(CFLAGS) -I../../src -o $@ $^

test: test_crypto test_quic_primitives test_preload
	./test_crypto
	./test_quic_primitives
	./test_preload

clean:
	rm -f test_crypto test_quic_primitives test_preload
