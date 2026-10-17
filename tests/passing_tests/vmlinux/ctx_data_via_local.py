# A local copied from a packet-pointer field is still a packet pointer: its
# slot is 64-bit and d + 14 is 64-bit pointer arithmetic.
from ctypes import c_int64, c_uint32  # noqa: F401
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    data = ctx.data
    eth = data + 14
    return c_int64(eth)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
