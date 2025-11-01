from ctypes import c_int64, c_int32
from pythonbpf import bpf, section, bpfglobal, compile_to_ir, compile
from vmlinux import struct_xdp_md
from vmlinux import XDP_PASS


@bpf
@section("xdp")
def print_xdp_data(ctx: struct_xdp_md) -> c_int64:
    data = ctx.data  # 32-bit field: packet start pointer
    something = c_int32(2 + data)
    print(f"ctx->data = {something}")
    return c_int64(XDP_PASS)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("i32_test.py", "i32_test.ll")
compile()
