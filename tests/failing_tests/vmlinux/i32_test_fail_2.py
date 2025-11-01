from ctypes import c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_xdp_md
from vmlinux import XDP_PASS
import logging


@bpf
@section("xdp")
def print_xdp_data(ctx: struct_xdp_md) -> c_int64:
    data = c_int64(ctx.data)  # 32-bit field: packet start pointer
    something = 2 + data
    print(f"ctx->data = {something}")
    return c_int64(XDP_PASS)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile(logging.INFO)
