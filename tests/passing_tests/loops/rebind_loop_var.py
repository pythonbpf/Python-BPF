# Rebinding the loop variable does not change the trip count: range() steps a
# counter of its own, as in Python. Returns 10.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    for i in range(10):
        total = total + 1
        i = 100  # noqa: F841 -- rebinding is the point of the test
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
