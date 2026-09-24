# Augmented assignment picks its operator from the promoted type like a
# binary operation does: on a c_uint32, >>= is a logical shift and //= and
# %= are unsigned division and remainder.
from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64, c_uint32


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    u = c_uint32(0xF0000000)
    u >>= 4  # lshr: 0x0F000000, not sign-filled
    u //= 3  # udiv
    u %= 7  # urem
    return c_int64(u)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
