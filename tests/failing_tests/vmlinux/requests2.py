from vmlinux import struct_request, struct_pt_regs, XDP_PASS
from pythonbpf import bpf, section, bpfglobal, compile_to_ir
import logging
from ctypes import c_int64


@bpf
@section("kprobe/blk_mq_start_request")
def example(ctx: struct_pt_regs) -> c_int64:
    req = ctx.di
    print(f"data length {req}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("requests2.py", "requests2.ll", loglevel=logging.INFO)
