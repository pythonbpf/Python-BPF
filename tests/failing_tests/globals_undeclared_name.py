# `global x` naming something that is not a @bpfglobal is a compile error.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global nosuch
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
