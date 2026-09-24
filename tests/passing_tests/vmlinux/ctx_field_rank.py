# A sub-register context field is loaded widened to i64, but C ranks it by
# its declared width: xdp_md.data is a u32, so data - k with a c_int32 k is
# a u32 subtraction (the result is cut to 32 bits and zero-extended), not a
# 64-bit one.
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
