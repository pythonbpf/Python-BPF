BPF_CLANG := clang
CFLAGS := -emit-llvm -target bpf -c

SRC := $(wildcard *.bpf.c)
LL := $(SRC:.bpf.c=.bpf.ll)
OBJ := $(SRC:.bpf.c=.bpf.o)
LL0 := $(SRC:.bpf.c=.bpf.o0.ll)
.PHONY: all clean

all: $(LL) $(OBJ) $(LL0)

%.bpf.o: %.bpf.c
	$(BPF_CLANG) -O2 -g -target bpf -c $< -o $@

%.bpf.ll: %.bpf.c
	$(BPF_CLANG) $(CFLAGS) -O2 -g -S $< -o $@

%.bpf.o0.ll: %.bpf.c
	$(BPF_CLANG) $(CFLAGS) -O0 -g -S $< -o $@

clean:
	rm -f $(LL) $(OBJ) $(LL0)
