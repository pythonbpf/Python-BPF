# A packet pointer stored into a 32-bit local is truncated, as in C
# (`__u32 x = ctx->data`), and is an ordinary integer from then on. The
# verifier forbids 32-bit arithmetic on a packet pointer, not a narrow store
# of one; upstream's cgroup_skb_direct_packet_access does the same with a
# __u32 global.
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
