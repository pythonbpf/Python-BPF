# A context field is loaded widened to i64, but it can be stored into a slot
# of its own declared width, or narrower: the store truncates like any other
# integer conversion. The cgroup_skb_direct_packet_access.c selftest does
# exactly this with `__u32 data_end = skb->data_end`.
from ctypes import c_int64, c_uint16, c_uint32
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md


@bpf
@bpfglobal
def ifindex() -> c_uint32:
    return c_uint32(0)


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    global ifindex
    ifindex = ctx.ingress_ifindex
    queue = c_uint16(0)
    queue = ctx.rx_queue_index
    return c_int64(queue)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
