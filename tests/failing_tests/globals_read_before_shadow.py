# The assignment below makes `counter` a local for the whole function, so the
# read above it is an UnboundLocalError in Python -- not a read of the global.
# There is no runtime here in which to raise that, so the compiler rejects the
# program instead of silently loading an uninitialised slot.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def counter() -> c_uint64:
    return c_uint64(7)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    print(f"counter {counter}")  # noqa: F821, F823 -- reads a local bound below
    counter = 1  # noqa: F841 -- ...here, which is what makes the read unbound
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
