# A step of 2**64 is a valid Python range() step (it yields just 0), but it
# does not fit the 64-bit counter: it truncates to 0 and the loop never ends.
# It should be a compile error.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    for i in range(0, 10, 18446744073709551616):
        total = total + 1
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
