# A helper's value carries the sign its registry entry declares: ktime()
# and pid() are unsigned, so a right shift is logical and a division is
# unsigned, the same as for a c_uint64 local.
from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import ktime, pid
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    t = ktime() >> 1  # lshr
    q = pid() // 3  # udiv
    return c_int64(t + q)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
