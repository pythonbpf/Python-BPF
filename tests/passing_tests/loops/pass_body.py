# `pass` is the natural body of a loop run only for its side effects, or of an
# else-branch kept for symmetry. Returns 3: the loop variable keeps its last
# value after the loop, as in Python.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    i: c_int64 = 0
    for i in range(4):
        pass
    else:
        pass
    return i


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
