# A local initialised from a vmlinux enum constant, the C shape
# `int act = XDP_PASS;`. Reads of a bare name resolve local, then BPF global,
# then vmlinux enum everywhere else; the allocation pass used to stop one step
# short for this shape and reject it, while `act = XDP_PASS + 0` compiled.
from ctypes import c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md
from vmlinux import XDP_PASS, XDP_DROP


@bpf
@section("xdp")
def prog(ctx: struct_xdp_md) -> c_int64:
    act = XDP_PASS
    if ctx.data_end - ctx.data > 1500:
        act = XDP_DROP
    return c_int64(act)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
