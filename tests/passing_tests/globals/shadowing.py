# Python's scoping rule, applied to BPF globals: assigning a name without a
# `global` statement creates a local that shadows the global for the whole
# function body, and leaves the global's storage alone. `tick` therefore writes
# a stack slot, and `read_back` still sees the initializer.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def counter() -> c_uint64:
    return c_uint64(7)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def tick(ctx: c_void_p) -> c_int64:
    counter = 1  # noqa: F841 -- no `global`, so this is a local; that is the test
    counter = counter + 1
    print(f"local counter {counter}")
    return c_int64(0)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def read_back(ctx: c_void_p) -> c_int64:
    # No assignment here, so the bare name is the global: still 7.
    print(f"global counter {counter}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
