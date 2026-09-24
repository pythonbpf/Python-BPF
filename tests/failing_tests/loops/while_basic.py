from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    i: c_int64 = 0
    while i < 10:
        i = i + 1
    return i


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
