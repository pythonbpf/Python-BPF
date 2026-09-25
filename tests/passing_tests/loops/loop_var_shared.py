# Where a loop variable is visible outside its loop it stays one local, as in
# Python: the outer body reads the `i` the inner loop left behind, and the
# return reads the last loop's final `i`. Each outer iteration adds 0 + 1 from
# the inner loop and 1 after it, the last loop adds 50, and the return adds 4:
# 6 + 50 + 4 = 60.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    for i in range(3):
        for i in range(2):
            total = total + i
        total = total + i
    for i in range(5):
        total = total + 10
    return total + i


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
