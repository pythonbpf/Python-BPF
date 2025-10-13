from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int32


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int32:
    print("Hello, World!")
    a = 1  # int64
    return c_int32(a)  # typecast to int32


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
