from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    if 0:
        print("Hello, World!")
    else:
        print("Goodbye, World!")
    return


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
