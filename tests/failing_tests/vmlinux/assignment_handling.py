from vmlinux import XDP_PASS
from pythonbpf import bpf, section, bpfglobal, compile_to_ir
import logging
from ctypes import c_int64, c_void_p


@bpf
@section("kprobe/blk_mq_start_request")
def example(ctx: c_void_p) -> c_int64:
    d = XDP_PASS # This gives an error, but
    e = XDP_PASS + 0 # this does not
    print(f"test1 {e} test2 {d}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("assignment_handling.py", "assignment_handling.ll", loglevel=logging.INFO)
