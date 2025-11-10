from vmlinux import struct_kobj_type
from pythonbpf import bpf, section, bpfglobal, compile_to_ir
import logging
from ctypes import c_void_p


@bpf
@section("kprobe/blk_mq_start_request")
def example(ctx: c_void_p):
    print(f"data lengt")


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("requests.py", "requests.ll", loglevel=logging.INFO)
