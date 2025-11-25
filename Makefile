CLANG ?= clang
CC ?= gcc

BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Wextra
BPF_SYS_INCLUDES ?= -isystem /usr/include/$(shell uname -m)-linux-gnu

XDP_SRC := xdp/mini_upf.c
XDP_OBJ := xdp/mini_upf.o

SEND_SRC := send_gtpu.c
SEND_BIN := send_gtpu

.PHONY: all clean

all: $(XDP_OBJ) $(SEND_BIN)

$(XDP_OBJ): $(XDP_SRC)
	$(CLANG) $(BPF_CFLAGS) $(BPF_SYS_INCLUDES) -c $< -o $@

$(SEND_BIN): $(SEND_SRC)
	$(CC) -O2 -Wall -Wextra -o $@ $<

clean:
	rm -f $(XDP_OBJ) $(SEND_BIN)
