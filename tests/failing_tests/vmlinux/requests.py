from vmlinux import struct_request, struct_pt_regs, XDP_PASS
from pythonbpf import bpf, section, bpfglobal, compile_to_ir
import logging


@bpf
@section("kprobe/blk_mq_start_request")
def example(ctx: struct_pt_regs):
    req = struct_request(ctx.di)
    c = req.__data_len
    d = XDP_PASS
    print(f"data length {c} and test {d}")


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("requests.py", "requests.ll", loglevel=logging.INFO)
