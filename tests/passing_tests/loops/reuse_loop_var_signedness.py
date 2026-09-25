# Two unrelated loops that reuse `i`. The first counts over an unsigned
# bound, the second over a signed one. The second loop's `i < 0` has to see
# -3, -2 and -1, not the unsigned slot the first loop left behind.
# Returns 3 + 3 * 100 = 303.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    n: c_uint64 = 3
    total: c_int64 = 0
    for i in range(n):
        total = total + 1
    for i in range(-3, 3):
        if i < 0:
            total = total + 100
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
