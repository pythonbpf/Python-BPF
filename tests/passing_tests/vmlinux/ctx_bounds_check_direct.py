# The same bounds check written on the fields directly.
from ctypes import c_int64, c_uint32  # noqa: F401
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    if ctx.data + 14 > ctx.data_end:
        return c_int64(1)
    return c_int64(2)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
