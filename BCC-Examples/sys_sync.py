from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_sync")
def hello_world(ctx: c_void_p) -> c_int64:
    print("sys_sync() called")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
print("Tracing sys_sync()... Ctrl-C to end.")
