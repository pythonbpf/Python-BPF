# xdp_md.data is declared u32, so C's rules make ctx.data - k a 32-bit
# subtraction, and that is what the compiler emits (w0 += -1). The verifier
# tracks data as a packet pointer and rejects it: "R0 32-bit pointer
# arithmetic prohibited". C hits the same and casts through (void *)(long).
# The planned fix gives the packet-pointer fields 64-bit pointer rank so no
# cast is needed; see the TODO in expr_pass._descriptor. The same u32 rank on
# a scalar field is pinned as passing in passing_tests/vmlinux/ctx_field_rank.py.
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
