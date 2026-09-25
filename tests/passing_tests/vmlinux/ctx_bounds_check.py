# The canonical XDP bounds check, through locals: the packet-pointer type
# travels with data and data_end, so data + 34 > data_end is a 64-bit
# unsigned comparison, which is what the verifier needs to prove the range.
from ctypes import c_int64, c_uint32  # noqa: F401
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    data = ctx.data
    data_end = ctx.data_end
    if data + 34 > data_end:
        return c_int64(1)
    return c_int64(2)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
