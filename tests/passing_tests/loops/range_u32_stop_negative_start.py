# The counter is 64-bit, and a 64-bit signed value holds every u32, so by
# C's own rules a u32 stop does not make the loop unsigned: in
# `for (__s64 idx = -1; idx < n; idx++)` n widens to __s64. Returns 4, as
# range(-1, 3) does in Python.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint32


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    n: c_uint32 = 3
    total: c_int64 = 0
    for i in range(-1, n):
        total = total + 1
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
