BPF_CLANG := clang
CFLAGS := -emit-llvm -target bpf -c

SRC := $(wildcard *.bpf.c)
LL := $(SRC:.bpf.c=.bpf.ll)
LL2 := $(SRC:.bpf.c=.bpf.o2.ll)
OBJ := $(SRC:.bpf.c=.bpf.o)

.PHONY: all clean

all: $(LL) $(OBJ) $(LL2)

%.bpf.o: %.bpf.c
	$(BPF_CLANG) -O2 -g -target bpf -c $< -o $@

%.bpf.ll: %.bpf.c
	$(BPF_CLANG) -O0 $(CFLAGS) -g -S $< -o $@

%.bpf.o2.ll: %.bpf.c
	$(BPF_CLANG) -O2 $(CFLAGS) -g -S $< -o $@

clean:
	rm -f $(LL) $(OBJ) $(LL2)
