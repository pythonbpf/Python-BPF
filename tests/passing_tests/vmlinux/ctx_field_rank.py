# A sub-register context field is loaded widened to i64, but C ranks it by
# its declared width: xdp_md.ingress_ifindex is a u32, so ifindex - k with a
# c_int32 k is a u32 subtraction (the result is cut to 32 bits and
# zero-extended), not a 64-bit one.
#
# Not xdp_md.data: it is a u32 in C too, but the verifier tracks it as a
# packet pointer and rejects 32-bit arithmetic on it ("R0 32-bit pointer
# arithmetic prohibited"), for C programs as much as for this one. That is
# why C casts it through (void *)(long) before doing anything with it.
from ctypes import c_int32, c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    k = c_int32(1)
    d = ctx.ingress_ifindex - k
    return c_int64(d)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
