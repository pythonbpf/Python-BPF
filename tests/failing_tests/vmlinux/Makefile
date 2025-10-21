BPF_CLANG := clang
CFLAGS := -O2 -emit-llvm -target bpf -c

SRC := $(wildcard *.bpf.c)
LL := $(SRC:.bpf.c=.bpf.ll)
OBJ := $(SRC:.bpf.c=.bpf.o)

.PHONY: all clean

all: $(LL) $(OBJ)

%.bpf.o: %.bpf.c
	$(BPF_CLANG) -O2 -g -target bpf -c $< -o $@

%.bpf.ll: %.bpf.c
	$(BPF_CLANG) $(CFLAGS) -g -S $< -o $@

clean:
	rm -f $(LL) $(OBJ)
