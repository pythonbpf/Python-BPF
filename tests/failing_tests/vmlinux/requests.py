from vmlinux import struct_request, struct_pt_regs
from pythonbpf import bpf, section, bpfglobal, compile_to_ir
import logging
from ctypes import c_int64


@bpf
@section("kprobe/blk_mq_start_request")
def example(ctx: struct_pt_regs) -> c_int64:
    req = struct_request(ctx.di)
    c = req.__data_len
    print(f"data length {c}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("requests.py", "requests.ll", loglevel=logging.INFO)
