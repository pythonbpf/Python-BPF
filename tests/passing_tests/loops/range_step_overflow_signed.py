# range() stops once the next value would pass stop; it never wraps. Here the
# first step overshoots INT64_MAX, so the counter must not wrap to a negative
# value that is still below stop; the second loop does the same below
# INT64_MIN. Leaving that way is a normal exit, so each else-branch runs.
# Returns 1 + 10 + 1 + 10 = 22.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def hello(ctx: c_void_p) -> c_int64:
    total: c_int64 = 0
    for i in range(9223372036854775806, 9223372036854775807, 2):
        total = total + 1
    else:
        total = total + 10
    for j in range(-9223372036854775807, -9223372036854775808, -3):
        total = total + 1
    else:
        total = total + 10
    return total


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
