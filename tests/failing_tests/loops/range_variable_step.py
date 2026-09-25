from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    step: c_int64 = 2
    for i in range(0, 10, step):
        total = total + i
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
