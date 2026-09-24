# A bool is a 1-bit integer to LLVM, and C's rules for it are not the integer
# ones: it widens to 0 or 1 (never sign-extends to -1), and an integer narrows
# to it by comparing with zero (2 is true), not by keeping the low bit.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    t = True
    n = True
    n = 2  # bool = 2 is true in C; truncation would make it false
    s = t + 1  # int + bool promotes the bool to int 1: 2, not 0
    return c_int64(t + n + s)  # 1 + 1 + 2 = 4, not -1 + 0 + 0


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
