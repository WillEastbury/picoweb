# picoweb Makefile
CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wshadow -Wpedantic -std=c11 -D_GNU_SOURCE \
           -fno-strict-aliasing -fstack-protector-strong
LDFLAGS ?=
LDLIBS  ?= -pthread

# Discover all sources, then carve out the alternate-backend file so
# `make` (epoll) and `make uring` (io_uring) each have exactly one
# server_worker_main definition.
ALL_SRC      := $(wildcard src/*.c)
URING_SRC    := src/server_uring.c
EPOLL_SRC    := src/server.c

.PHONY: all clean run debug uring

# Default: epoll backend.
SRC := $(filter-out $(URING_SRC),$(ALL_SRC))
OBJ := $(SRC:.c=.o)
BIN := picoweb

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wshadow -Wpedantic -std=c11 \
                 -D_GNU_SOURCE -fno-strict-aliasing \
                 -fsanitize=address,undefined
debug: LDLIBS += -fsanitize=address,undefined
debug: clean $(BIN)

# io_uring backend. Builds picoweb_uring with server_uring.c instead
# of server.c. Requires Linux kernel 5.6+ and <linux/io_uring.h>
# (kernel headers — no liburing dependency).
URING_OBJ := $(filter-out $(EPOLL_SRC:.c=.o),$(ALL_SRC:.c=.o))
uring: BIN := picoweb_uring
uring: clean
	$(MAKE) URING_BUILD=1 picoweb_uring

picoweb_uring: $(URING_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

run: $(BIN)
	./$(BIN) 8080 wwwroot

clean:
	rm -f src/*.o picoweb picoweb_uring
