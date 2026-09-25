# data_end can only be compared against; the verifier rejects arithmetic on
# it, so the compiler refuses it.
from ctypes import c_int64, c_uint32  # noqa: F401
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    e = ctx.data_end + 1
    return c_int64(e)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
