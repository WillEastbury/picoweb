# picoweb Makefile
CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Wshadow -Wpedantic -std=c11 -D_GNU_SOURCE \
           -fno-strict-aliasing -fstack-protector-strong
LDFLAGS ?=
LDLIBS  ?= -pthread

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
debug: clean $(BIN)

run: $(BIN)
	./$(BIN) 8080 wwwroot

clean:
	rm -f $(OBJ) $(BIN)
