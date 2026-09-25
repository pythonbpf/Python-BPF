# A return inside an if-branch is lowered in the function's declared return
# type (i32 here), not a default i64 that llc rejects.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int32


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int32:
    x = 1
    if x == 1:
        return 7
    return 0


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
