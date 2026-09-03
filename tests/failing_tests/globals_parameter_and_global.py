# Declaring a parameter `global` is a SyntaxError in Python itself
# ("name 'ctx' is parameter and global"), and the compiler must say the same:
# otherwise reads (local first) and writes would resolve `ctx` to different
# storage.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@bpfglobal
def ctx() -> c_uint64:
    return c_uint64(0)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:  # noqa: F811 -- the collision is the test
    global ctx  # noqa: F811
    ctx += 1
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
