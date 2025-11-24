from vmlinux import struct_request, struct_pt_regs
from pythonbpf import bpf, section, bpfglobal, compile_to_ir, compile, map
from pythonbpf.helper import ktime
from pythonbpf.maps import HashMap
import logging
from ctypes import c_int64, c_uint64, c_uint32, c_int32

# Constants
REQ_WRITE = 1  # from include/linux/blk_types.h

@bpf
@map
def start() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=10240)

@bpf
@section("kprobe/blk_mq_end_request")
def trace_completion(ctx: struct_pt_regs) -> c_int64:
    # Get request pointer from first argument
    req_ptr = ctx.di
    req = struct_request(ctx.di)
    # Print: data_len, cmd_flags, latency_us
    data_len = req.__data_len
    cmd_flags = req.cmd_flags
    # Lookup start timestamp
    req_tsp = start.lookup(req_ptr)
    if req_tsp:
        # Calculate delta in nanoseconds
        delta = ktime() - req_tsp

        # Convert to microseconds for printing
        delta_us = delta // 1000

        print(f"{data_len} {cmd_flags:x} {delta_us}\n")

        # Delete the entry
        start.delete(req_ptr)

    return c_int64(0)

@bpf
@section("kprobe/blk_mq_start_request")
def trace_start(ctx1: struct_pt_regs) -> c_int32:
    req = ctx1.di
    ts = ktime()
    start.update(req, ts)
    return c_int32(0)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


if __name__ == "__main__":
    compile_to_ir("disksnoop.py", "disksnoop.ll", loglevel=logging.INFO)
    compile()
