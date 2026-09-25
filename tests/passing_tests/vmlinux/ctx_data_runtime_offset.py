# A runtime offset added to a packet pointer is taken as an unsigned 16-bit
# value (masked to 0xffff, zero-extended), so the verifier can bound the
# packet range; the addition itself is 64-bit.
from ctypes import c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import random
from vmlinux import struct_xdp_md


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    off = random()
    d = ctx.data + off
    return c_int64(d)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
