from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64
from pythonbpf.helper import XDP_PASS


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello_world(ctx: c_void_p) -> c_int64:
    print("Hello, World!")
    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
