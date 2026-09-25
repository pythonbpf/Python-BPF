# The only way out of `while True` is the return in its body, so the block
# after the loop is unreachable. Whatever closes it off has to match the
# function's c_int32 return type. Returns 6.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int32


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int32:
    i: c_int32 = 0
    while True:
        i = i + 1
        if i > 5:
            return i


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
