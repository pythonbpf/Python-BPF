from pythonbpf import compile, bpf, section, bpfglobal
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def sometag(ctx: c_void_p) -> c_int64:
    if 3 + 2 == 5:
        return c_int64(5)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
