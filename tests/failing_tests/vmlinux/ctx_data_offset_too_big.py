# 70000 cannot be a packet offset: the verifier tracks packet ranges only
# up to 0xffff. Rejected at compile time rather than silently wrapped.
from ctypes import c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    d = ctx.data + 70000
    return c_int64(d)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
