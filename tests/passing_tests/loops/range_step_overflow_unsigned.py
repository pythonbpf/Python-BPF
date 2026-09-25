# The unsigned version of range_step_overflow_signed: the step goes past
# UINT64_MAX, and the counter must not wrap to 0, which is below stop. Returns 1.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    stop: c_uint64 = 18446744073709551615
    total: c_int64 = 0
    for i in range(18446744073709551614, stop, 2):
        total = total + 1
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
