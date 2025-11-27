from vmlinux import XDP_PASS, XDP_ABORTED
from vmlinux import (
    struct_xdp_md,
)
from pythonbpf import bpf, section, bpfglobal, compile, compile_to_ir, struct
from ctypes import c_int64, c_ubyte, c_ushort, c_uint32, c_void_p


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
    data = c_void_p(ctx.data)
    data_end = c_void_p(ctx.data_end)
    if data + 34 < data_end:
        hdr = data + 14
        iph = iphdr(hdr)
        addr = iph.saddr
        print(f"ipaddress: {addr}")
    else:
        return c_int64(XDP_ABORTED)

    return c_int64(XDP_PASS)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("xdp_test_1.py", "xdp_test_1.ll")
compile()
