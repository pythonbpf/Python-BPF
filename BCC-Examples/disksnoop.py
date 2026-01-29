from ctypes import c_int32, c_int64, c_uint64

from vmlinux import struct_pt_regs, struct_request

from pythonbpf import bpf, bpfglobal, compile, map, section
from pythonbpf.helper import ktime
from pythonbpf.maps import HashMap


@bpf
@map
def start() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=10240)


@bpf
@section("kprobe/blk_mq_end_request")
def trace_completion(ctx: struct_pt_regs) -> c_int64:
    req_ptr = ctx.di
    req = struct_request(ctx.di)
    data_len = req.__data_len
    cmd_flags = req.cmd_flags
    req_tsp = start.lookup(req_ptr)
    if req_tsp:
        delta = ktime() - req_tsp
        delta_us = delta // 1000
        print(f"{data_len} {cmd_flags:x} {delta_us}\n")
        start.delete(req_ptr)

    return 0  # type: ignore [return-value]


@bpf
@section("kprobe/blk_mq_start_request")
def trace_start(ctx1: struct_pt_regs) -> c_int32:
    req = ctx1.di
    ts = ktime()
    start.update(req, ts)
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
