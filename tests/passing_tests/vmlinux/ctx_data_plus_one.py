# Adding a constant to a packet pointer is 64-bit pointer arithmetic
# (r0 += 1), not the u32 addition C's integer rules would give xdp_md.data.
from ctypes import c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    d = ctx.data + 1
    return c_int64(d)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
