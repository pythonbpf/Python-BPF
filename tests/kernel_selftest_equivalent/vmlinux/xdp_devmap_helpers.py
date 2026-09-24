# Ported from Linux tools/testing/selftests/bpf/progs/test_xdp_devmap_helpers.c
#
# Reads xdp_md->egress_ifindex, which only exists for programs loaded with
# expected_attach_type = BPF_XDP_DEVMAP. Upstream loads it *without* that
# type and asserts the load fails, so the program is a negative fixture:
#
#     unsigned int len = data_end - data;
#     bpf_trace_printk(fmt, sizeof(fmt),
#                      ctx->ingress_ifindex, ctx->egress_ifindex, len);
#     return XDP_PASS;

from pythonbpf import bpf, section, bpfglobal, compile
from pythonbpf.helper import XDP_PASS
from vmlinux import struct_xdp_md
from ctypes import c_int64


@bpf
@section("xdp")
def xdpdm_devlog(ctx: struct_xdp_md) -> c_int64:
    length = ctx.data_end - ctx.data
    ingress = ctx.ingress_ifindex
    egress = ctx.egress_ifindex
    print(f"devmap redirect: dev {ingress} -> dev {egress} len {length}")
    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
