# A loop's else-branch runs when the loop ends without a break: the for loop
# never breaks, so its else adds 100; the while loop breaks, so its else is
# skipped. Returns 3 + 100 + 1 = 104.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    for i in range(3):
        if i == 7:
            break
        total = total + 1
    else:
        total = total + 100
    while total < 1000:
        total = total + 1
        break
    else:
        total = total + 1000
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
