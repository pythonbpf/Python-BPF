from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    if total == 0:
        break  # noqa: F701 -- the point of the test
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
