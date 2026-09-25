# data_meta is a packet-metadata pointer; offsets are allowed on it too.
from ctypes import c_int64, c_uint32  # noqa: F401
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    m = ctx.data_meta + 4
    return c_int64(m)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
