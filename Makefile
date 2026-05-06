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
SRC := $(wildcard src/*.c)
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
