# Pointer minus pointer is a length: an ordinary 64-bit subtraction, with no
# 16-bit clamp on either side.
from ctypes import c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    n = ctx.data_end - ctx.data
    return c_int64(n)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
