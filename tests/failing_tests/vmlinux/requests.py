from vmlinux import struct_request, struct_pt_regs
from pythonbpf import bpf, section, bpfglobal, compile_to_ir, compile
import logging
from ctypes import c_int64


@bpf
@section("kprobe/blk_mq_start_request")
def example(ctx: struct_pt_regs) -> c_int64:
    a = ctx.r15
    req = struct_request(ctx.di)
    d = req.__data_len
    b = ctx.r12
    c = req.timeout
    print(f"data length {d} and {c} and {a}")
    print(f"ctx arg {b}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("requests.py", "requests.ll", loglevel=logging.INFO)
compile()
