from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    a = 2
    return a - 2


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
