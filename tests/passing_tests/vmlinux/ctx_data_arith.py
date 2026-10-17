# xdp_md.data is declared u32, but the verifier treats it as a packet pointer
# and prohibits 32-bit arithmetic on it. C's integer rules would rank
# ctx.data - k as a u32 subtraction (w0 += -1, rejected with "R0 32-bit
# pointer arithmetic prohibited"); the compiler special-cases packet-pointer
# fields instead (pythonbpf/expr/packet_pointer.py): 64-bit arithmetic, the
# offset taken as u16, so this is r0 += -1 and no cast is needed.
from ctypes import c_int32, c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    k = c_int32(1)
    d = ctx.data - k
    return c_int64(d)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
