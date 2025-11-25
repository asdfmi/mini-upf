CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Wextra
BPF_SYS_INCLUDES ?= -isystem /usr/include/$(shell uname -m)-linux-gnu

XDP_SRC := xdp/mini_upf.c
XDP_OBJ := xdp/mini_upf.o

.PHONY: all clean

all: $(XDP_OBJ)

$(XDP_OBJ): $(XDP_SRC)
	$(CLANG) $(BPF_CFLAGS) $(BPF_SYS_INCLUDES) -c $< -o $@

clean:
	rm -f $(XDP_OBJ)
