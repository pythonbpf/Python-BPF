# A packet pointer stored into a 32-bit slot would lose it; the verifier only
# accepts packet pointers at 64 bits, so the compiler refuses the narrowing.
from ctypes import c_int64, c_uint32  # noqa: F401
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    x = c_uint32(0)
    x = ctx.data
    return c_int64(x)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
