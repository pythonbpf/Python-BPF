from vmlinux import XDP_PASS, XDP_DROP
from vmlinux import (
    struct_xdp_md,
    struct_ethhdr,
)
from pythonbpf import bpf, section, bpfglobal, compile, compile_to_ir, struct
from ctypes import c_int64, c_ubyte, c_ushort, c_uint32


@bpf
@struct
class iphdr:
    useless: c_ushort
    tot_len: c_ushort
    id: c_ushort
    frag_off: c_ushort
    ttl: c_ubyte
    protocol: c_ubyte
    check: c_ushort
    saddr: c_uint32
    daddr: c_uint32


@bpf
@section("xdp")
def ip_detector(ctx: struct_xdp_md) -> c_int64:
    data = ctx.data
    data_end = ctx.data_end
    if data + 14 > data_end:
        return c_int64(XDP_DROP)

    eth = struct_ethhdr(data)
    nh = data + 14
    if nh + 20 > data_end:
        return c_int64(XDP_DROP)

    iph = iphdr(nh)

    print(f"ipaddress: {iph.saddr}")

    return c_int64(XDP_PASS)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("xdp_test_1.py", "xdp_test_1.ll")
compile()
